import { EXIT_CODES } from "./exit-codes.mjs";
import { chmodSync, closeSync, existsSync, fchmodSync, fstatSync, linkSync, lstatSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";

const WINDOWS_OWNER_ACL_CHECK = `function Test-OwnerAcl($acl, $user) {
  $rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
  return ($acl.AreAccessRulesProtected -and
    $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -eq $user.Value -and
    $rules.Count -eq 1 -and
    $rules[0].IdentityReference.Value -eq $user.Value -and
    $rules[0].AccessControlType -eq "Allow" -and
    $rules[0].FileSystemRights -eq "FullControl")
}`;

// Only metadata snapshots that this process has already protected are cached.
const protectedPaths = new Map();

function permissionError(message) {
  const error = new Error("PRIVATE_PERMISSIONS: " + message);
  error.code = "PRIVATE_PERMISSIONS";
  error.errorCode = error.code;
  error.exitCode = EXIT_CODES.INTEGRITY_VIOLATION;
  return error;
}

function snapshot(path) {
  const stat = lstatSync(path, { bigint: true });
  if (stat.isSymbolicLink()) throw permissionError("Refusing a symbolic-link credential path");
  return [stat.dev, stat.ino, stat.ctimeNs, stat.mtimeNs, stat.size, stat.mode].join(":");
}

/** Protect existing files/directories and verify the resulting access policy. */
export function protectPrivatePaths(paths) {
  const pending = [...new Set(paths.map(path => resolve(path)))]
    .filter(path => protectedPaths.get(path) !== snapshot(path));
  if (pending.length === 0) return;
  if (process.platform === "win32") {
    const targets = pending.map(path => ({ path, directory: lstatSync(path).isDirectory() }));
    const encoded = Buffer.from(JSON.stringify(targets), "utf8").toString("base64");
    const script = `
$ErrorActionPreference = "Stop"
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$user = $identity.User
$tokenOwner = $identity.Owner
$targets = ConvertFrom-Json ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("${encoded}")))
${WINDOWS_OWNER_ACL_CHECK}
foreach ($target in $targets) {
  if ($target.directory) { $current = [IO.Directory]::GetAccessControl($target.path) }
  else { $current = [IO.File]::GetAccessControl($target.path) }
  $owner = $current.GetOwner([System.Security.Principal.SecurityIdentifier])
  if ($owner.Value -ne $user.Value -and $owner.Value -ne $tokenOwner.Value) {
    throw "Credential path belongs to another identity"
  }
  if (!(Test-OwnerAcl $current $user)) {
    if ($target.directory) {
      $acl = New-Object System.Security.AccessControl.DirectorySecurity
      $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($user, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    } else {
      $acl = New-Object System.Security.AccessControl.FileSecurity
      $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($user, "FullControl", "Allow")
    }
    # Writing the owner needs WRITE_OWNER, which owners do not implicitly hold;
    # only rewrite it when the recorded owner is not already this user.
    if ($owner.Value -ne $user.Value) { $acl.SetOwner($user) }
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule($rule)
    if ($target.directory) {
      [IO.Directory]::SetAccessControl($target.path, $acl)
      $current = [IO.Directory]::GetAccessControl($target.path)
    } else {
      [IO.File]::SetAccessControl($target.path, $acl)
      $current = [IO.File]::GetAccessControl($target.path)
    }
  }
  if (!(Test-OwnerAcl $current $user)) {
    throw "Owner-only credential ACL could not be verified"
  }
}
Write-Output "MIRQL_PRIVATE_ACL_OK"
`;
    runGuardedPowerShell(script, { okToken: "MIRQL_PRIVATE_ACL_OK", failureHint: "ACL enforcement failed" });
  } else {
    for (const path of pending) {
      const mode = lstatSync(path).isDirectory() ? 0o700 : 0o600;
      chmodSync(path, mode);
      if ((lstatSync(path).mode & 0o777) !== mode) {
        throw permissionError("Owner-only mode could not be verified for " + path);
      }
    }
  }
  for (const path of pending) protectedPaths.set(path, snapshot(path));
}

/** Windows creates a private file atomically and writes through that same handle. */
function stageWindowsFiles(files) {
  const script = `
$ErrorActionPreference = "Stop"
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
${WINDOWS_OWNER_ACL_CHECK}
$files = ConvertFrom-Json ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([Console]::In.ReadToEnd())))
foreach ($file in $files) {
  $acl = New-Object System.Security.AccessControl.FileSecurity
  $acl.SetOwner($user)
  $acl.SetAccessRuleProtection($true, $false)
  $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($user, "FullControl", "Allow")))
  $stream = [IO.FileStream]::new($file.temp, [IO.FileMode]::CreateNew,
    [Security.AccessControl.FileSystemRights]::FullControl, [IO.FileShare]::None,
    4096, [IO.FileOptions]::None, $acl)
  try {
    if (!(Test-OwnerAcl $stream.GetAccessControl() $user)) { throw "Private file handle ACL is invalid" }
    $bytes = [Convert]::FromBase64String($file.contentsBase64)
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush($true)
  } finally { $stream.Dispose() }
}
Write-Output "MIRQL_PRIVATE_WRITE_OK"
`;
  const input = Buffer.from(JSON.stringify(files.map(file => ({
    temp: file.temp, contentsBase64: Buffer.from(file.contents, "utf8").toString("base64"),
  }))), "utf8").toString("base64");
  runGuardedPowerShell(script, { input, okToken: "MIRQL_PRIVATE_WRITE_OK", failureHint: "Private handle publication failed" });
}

/**
 * Runs one hidden PowerShell guard script and fails closed unless it reports
 * okToken. A short first deadline keeps genuinely broken setups fast; a single
 * extended retry absorbs ETIMEDOUT stalls observed when many tests cold-start
 * PowerShell under parallel CPU contention (Windows). Verification semantics
 * are unchanged: any remaining failure still refuses credential publication.
 */
function runGuardedPowerShell(script, { input, okToken, failureHint }) {
  const executable = join(process.env.SystemRoot ?? "C:\\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
  const args = ["-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(script, "utf16le").toString("base64")];
  let result = spawnSync(executable, args, { input, encoding: "utf8", timeout: 30000, windowsHide: true });
  if (result.error?.code === "ETIMEDOUT") {
    result = spawnSync(executable, args, { input, encoding: "utf8", timeout: 120000, windowsHide: true });
  }
  if (result.error || result.status !== 0 || result.stdout.trim() !== okToken) {
    throw permissionError(result.error?.message ?? result.stderr.trim() ?? failureHint);
  }
}

function assertSameFile(file) {
  const handle = fstatSync(file.fd);
  const path = lstatSync(file.temp);
  if (!path.isFile() || handle.dev !== path.dev || handle.ino !== path.ino) {
    throw permissionError("Credential temporary pathname was replaced");
  }
}

/** Publish credentials after writing through a private, exclusively created handle. */
export function writePrivateFiles(files, { directories = [], exclusive = false } = {}) {
  const protectedDirectories = new Set(directories.map(path => resolve(path)));
  const staged = [];
  try {
    for (const { path, contents } of files) {
      const destination = resolve(path);
      const parent = dirname(destination);
      if (!existsSync(parent)) protectedDirectories.add(parent);
      mkdirSync(parent, { recursive: true, mode: 0o700 });
      let existing = false;
      try {
        const stat = lstatSync(destination);
        existing = true;
        if (!stat.isFile()) throw permissionError("Credential destination must be a regular file");
      } catch (error) {
        if (error.code !== "ENOENT") throw error;
      }
      const temp = destination + "." + randomUUID() + ".tmp";
      const fd = process.platform === "win32" ? undefined : openSync(temp, "wx", 0o600);
      staged.push({ destination, existing, temp, contents, fd });
    }
    protectPrivatePaths([
      ...protectedDirectories,
      ...staged.filter(file => file.existing && !exclusive).map(file => file.destination),
    ]);
    if (process.platform === "win32" && staged.length) {
      stageWindowsFiles(staged);
      protectPrivatePaths(staged.map(file => file.temp));
    }
    for (const file of staged) {
      if (process.platform === "win32") {
        file.fd = openSync(file.temp, "r");
        assertSameFile(file);
        if (!readFileSync(file.fd).equals(Buffer.from(file.contents, "utf8"))) {
          throw permissionError("Credential temporary contents were replaced");
        }
      } else {
        fchmodSync(file.fd, 0o600);
        if ((fstatSync(file.fd).mode & 0o777) !== 0o600) throw permissionError("Private handle mode is invalid");
        assertSameFile(file);
        writeFileSync(file.fd, file.contents, "utf8");
      }
      assertSameFile(file);
      if (exclusive) linkSync(file.temp, file.destination);
      else renameSync(file.temp, file.destination);
      const published = lstatSync(file.destination);
      const handle = fstatSync(file.fd);
      if (!published.isFile() || published.dev !== handle.dev || published.ino !== handle.ino) {
        throw permissionError("Published credential pathname was replaced");
      }
      protectedPaths.set(file.destination, snapshot(file.destination));
      protectedPaths.delete(file.temp);
    }
  } finally {
    for (const file of staged) {
      if (file.fd !== undefined) closeSync(file.fd);
      try { unlinkSync(file.temp); } catch (error) { if (error.code !== "ENOENT") throw error; }
      protectedPaths.delete(file.temp);
    }
  }
  for (const path of protectedDirectories) protectedPaths.set(path, snapshot(path));
}

export function writePrivateFile(path, contents, options) {
  writePrivateFiles([{ path, contents }], options);
}
