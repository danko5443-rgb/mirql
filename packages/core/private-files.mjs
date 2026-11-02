import { EXIT_CODES } from "./exit-codes.mjs";
import { chmodSync, existsSync, linkSync, lstatSync, mkdirSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";

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
function Test-OwnerAcl($acl, $user) {
  $rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
  return ($acl.AreAccessRulesProtected -and
    $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -eq $user.Value -and
    $rules.Count -eq 1 -and
    $rules[0].IdentityReference.Value -eq $user.Value -and
    $rules[0].AccessControlType -eq "Allow" -and
    $rules[0].FileSystemRights -eq "FullControl")
}
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
    $acl.SetOwner($user)
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
    const executable = join(process.env.SystemRoot ?? "C:\\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
    const result = spawnSync(executable, [
      "-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(script, "utf16le").toString("base64"),
    ], { encoding: "utf8", timeout: 30000, windowsHide: true });
    if (result.error || result.status !== 0 || result.stdout.trim() !== "MIRQL_PRIVATE_ACL_OK") {
      throw permissionError(result.error?.message ?? result.stderr.trim() ?? "ACL enforcement failed");
    }
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

/** Publish credentials only after their temporary files have verified permissions. */
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
      writeFileSync(temp, "", { mode: 0o600, flag: "wx" });
      staged.push({ destination, existing, temp, contents });
    }
    protectPrivatePaths([
      ...protectedDirectories,
      ...staged.filter(file => file.existing).map(file => file.destination),
      ...staged.map(file => file.temp),
    ]);
    for (const file of staged) {
      writeFileSync(file.temp, file.contents, "utf8");
      if (exclusive) linkSync(file.temp, file.destination);
      else renameSync(file.temp, file.destination);
      // Rename preserves the protected temporary file's ACL.
      protectedPaths.set(file.destination, snapshot(file.destination));
      protectedPaths.delete(file.temp);
    }
  } finally {
    for (const file of staged) {
      if (existsSync(file.temp)) unlinkSync(file.temp);
      protectedPaths.delete(file.temp);
    }
  }
  for (const path of protectedDirectories) protectedPaths.set(path, snapshot(path));
}

export function writePrivateFile(path, contents, options) {
  writePrivateFiles([{ path, contents }], options);
}
