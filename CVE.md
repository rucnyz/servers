# Security Vulnerability Report: Filesystem MCP Server

## Summary

| Field | Value |
|-------|-------|
| **Affected Component** | `@modelcontextprotocol/server-filesystem` |
| **Affected Versions** | < 0.6.3, < 2025.3.28 |
| **Fixed Versions** | 0.6.4, 2025.7.01 |
| **Severity** | High |
| **Vulnerability Type** | Path Traversal, Symlink Following, TOCTOU Race Condition |
| **Reporter** | Elad Beber (Cymulate) |
| **Fix Commit** | [d00c60df9d74dba8a3bb13113f8904407cda594f](https://github.com/modelcontextprotocol/servers/commit/d00c60df9d74dba8a3bb13113f8904407cda594f) |

---

## Vulnerability Description

The Filesystem MCP Server provides file system access capabilities to MCP clients. It accepts a list of allowed directories as command-line arguments and is designed to restrict all file operations to within those directories.

Two critical vulnerabilities were discovered that allow attackers to bypass the directory restrictions and access files outside the allowed directories.

---

## Vulnerability 1: Path Prefix Bypass

### Description

The `validatePath()` function uses JavaScript's `String.prototype.startsWith()` method to check if a requested path is within an allowed directory. This check is insufficient because it does not enforce directory boundaries.

### Vulnerable Code

**File:** `src/filesystem/index.ts` (Line 66)

```typescript
// Security utilities
async function validatePath(requestedPath: string): Promise<string> {
  const expandedPath = expandHome(requestedPath);
  const absolute = path.isAbsolute(expandedPath)
    ? path.resolve(expandedPath)
    : path.resolve(process.cwd(), expandedPath);

  const normalizedRequested = normalizePath(absolute);

  // VULNERABLE: Simple prefix check without directory boundary enforcement
  const isAllowed = allowedDirectories.some(dir => normalizedRequested.startsWith(dir));
  if (!isAllowed) {
    throw new Error(`Access denied - path outside allowed directories`);
  }
  // ...
}
```

### Attack Scenario

**Configuration:**
```bash
# Server started with allowed directory
npx @modelcontextprotocol/server-filesystem /home/user/project
```

**Attack:**
```
Allowed directory:     /home/user/project
Attacker requests:     /home/user/project2/sensitive-data.txt
                       /home/user/project_backup/secrets.env
                       /home/user/projectile/config.json
```

All of these paths pass the `startsWith()` check because they all begin with `/home/user/project`.

### Proof of Concept

```typescript
// Simulating the vulnerable check
const allowedDirectories = ['/home/user/project'];

function vulnerableCheck(requestedPath: string): boolean {
  return allowedDirectories.some(dir => requestedPath.startsWith(dir));
}

// These all incorrectly return true
console.log(vulnerableCheck('/home/user/project'));        // true (correct)
console.log(vulnerableCheck('/home/user/project/src'));    // true (correct)
console.log(vulnerableCheck('/home/user/project2'));       // true (VULNERABLE!)
console.log(vulnerableCheck('/home/user/project_backup')); // true (VULNERABLE!)
console.log(vulnerableCheck('/home/user/projectile'));     // true (VULNERABLE!)
```

### Impact

An attacker can read, write, or modify files in any directory that shares a common prefix with an allowed directory. This could lead to:

- **Information Disclosure:** Reading sensitive files from adjacent directories
- **Data Tampering:** Modifying configuration files or code in sibling projects
- **Privilege Escalation:** If a sibling directory contains executable scripts or configuration

---

## Vulnerability 2: Symlink Following with TOCTOU Race Condition

### Description

While the vulnerable code does attempt to validate symlink targets using `fs.realpath()`, there is a Time-of-Check to Time-of-Use (TOCTOU) race condition between the validation and the actual file operation.

### Vulnerable Code

**File:** `src/filesystem/index.ts` (Lines 71-79, 487-488)

```typescript
// In validatePath():
try {
  const realPath = await fs.realpath(absolute);
  const normalizedReal = normalizePath(realPath);
  const isRealPathAllowed = allowedDirectories.some(dir => normalizedReal.startsWith(dir));
  if (!isRealPathAllowed) {
    throw new Error("Access denied - symlink target outside allowed directories");
  }
  return realPath;  // Returns the real path, but...
} catch (error) {
  // ...
}

// In write_file handler:
const validPath = await validatePath(parsed.data.path);
// TOCTOU GAP: Symlink could be created/modified here
await fs.writeFile(validPath, parsed.data.content, "utf-8");  // Follows symlinks!
```

### Attack Scenario

**Race Condition Attack:**

```
Timeline:
─────────────────────────────────────────────────────────────────────
T1: Attacker requests write to /allowed/file.txt
T2: validatePath() checks /allowed/file.txt - passes validation
T3: validatePath() returns valid path
    ┌─────────────────────────────────────────────────┐
T4: │ ATTACKER: rm /allowed/file.txt                  │  ← Race Window
T5: │ ATTACKER: ln -s /etc/passwd /allowed/file.txt   │
    └─────────────────────────────────────────────────┘
T6: fs.writeFile() writes to /allowed/file.txt
T7: Symlink is followed → /etc/passwd is overwritten!
─────────────────────────────────────────────────────────────────────
```

### Symlink Creation Attack

Even without a race condition, if an attacker can create symlinks within an allowed directory (e.g., via another tool or process), they can:

1. Create a symlink: `/allowed/evil -> /etc/passwd`
2. Request the server to read `/allowed/evil`
3. The server reads `/etc/passwd` through the symlink

While the code checks `realpath()`, the combination with the path prefix vulnerability (Vulnerability 1) makes this exploitable.

### Impact

- **Arbitrary File Read:** Read any file on the system through symlinks
- **Arbitrary File Write:** Overwrite critical system files
- **System Compromise:** Potential for full system takeover if writing to sensitive locations

---

## Fix Analysis

### Fix 1: Proper Directory Boundary Checking

**New File:** `src/filesystem/path-validation.ts`

```typescript
export function isPathWithinAllowedDirectories(
  absolutePath: string,
  allowedDirectories: string[]
): boolean {
  // ... input validation ...

  // Normalize paths
  const normalizedPath = path.resolve(path.normalize(absolutePath));

  return allowedDirectories.some(dir => {
    const normalizedDir = path.resolve(path.normalize(dir));

    // Check if path is exactly the allowed directory
    if (normalizedPath === normalizedDir) {
      return true;
    }

    // Check if path is within allowed directory WITH separator
    // This prevents /project matching /project2
    return normalizedPath.startsWith(normalizedDir + path.sep);
  });
}
```

**Key Change:** Adding `+ path.sep` ensures that `/home/user/project` only matches paths like `/home/user/project/...` and not `/home/user/project2`.

### Fix 2: Atomic File Operations

```typescript
// For write_file - use exclusive creation flag for new files
await fs.writeFile(validPath, content, { encoding: "utf-8", flag: 'wx' });

// For existing files - use atomic rename
const tempPath = `${validPath}.${randomBytes(16).toString('hex')}.tmp`;
try {
  await fs.writeFile(tempPath, content, 'utf-8');
  await fs.rename(tempPath, validPath);  // Atomic, doesn't follow symlinks
} catch (error) {
  await fs.unlink(tempPath).catch(() => {});
  throw error;
}
```

**Key Changes:**
- `wx` flag: Exclusive creation, fails if file/symlink exists
- Atomic rename: `fs.rename()` replaces the target atomically and does not follow symlinks

### Fix 3: Additional Security Hardening

```typescript
// Null byte injection prevention
if (absolutePath.includes('\x00')) {
  return false;
}

// Resolve symlinks in allowed directories at startup
const allowedDirectories = await Promise.all(
  args.map(async (dir) => {
    const resolved = await fs.realpath(path.resolve(expandHome(dir)));
    return normalizePath(resolved);
  })
);
```

---

## Comparison: Vulnerable vs Fixed

| Aspect | Vulnerable (< 0.6.3) | Fixed (>= 0.6.4) |
|--------|---------------------|------------------|
| Path boundary check | `startsWith(dir)` | `startsWith(dir + path.sep)` |
| File write | Direct `writeFile()` | Atomic temp + rename |
| New file creation | Standard mode | Exclusive mode (`wx`) |
| Null byte handling | Not checked | Rejected |
| Allowed dir symlinks | Resolved at access | Resolved at startup |

---

## Recommendations

### For Users

1. **Upgrade immediately** to version 0.6.4 or 2025.7.01
2. **Audit logs** for suspicious file access patterns
3. **Review allowed directories** configuration for overly permissive settings

### For Developers

1. **Never use `startsWith()` alone** for path validation
2. **Always append path separator** when checking directory containment
3. **Use atomic operations** for security-sensitive file writes
4. **Resolve symlinks at configuration time**, not at access time
5. **Consider using `O_NOFOLLOW`** flags where available

---

## References

- [Fix Commit](https://github.com/modelcontextprotocol/servers/commit/d00c60df9d74dba8a3bb13113f8904407cda594f)
- [Model Context Protocol Servers Repository](https://github.com/modelcontextprotocol/servers)
- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [CWE-59: Symlink Following](https://cwe.mitre.org/data/definitions/59.html)
- [CWE-367: TOCTOU Race Condition](https://cwe.mitre.org/data/definitions/367.html)

---

## Timeline

| Date | Event |
|------|-------|
| 2025-03-19 | Vulnerable version (tag: 2025.3.19) |
| 2025-03-28 | Fix released (tag: 2025.3.28) |
| 2025-06-30 | Fix commit merged |
| 2025-07-01 | Fixed version (tag: 2025.7.01) |

---

## Credits

- **Vulnerability Discovery:** Elad Beber (Cymulate)
- **Fix Implementation:** Jenn Newton (Anthropic)