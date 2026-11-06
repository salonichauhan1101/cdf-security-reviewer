# Security Assessment Report

## 1. Assessment Information

**Application:** CDF TaskFlow

**Assessment Type:** AI-Assisted Static Code Review

**Assessment Date:** 2026-11-06

**AI Model:** gemini-3.5-flash-lite

## 2. Executive Summary

The source code was analyzed to identify potential security weaknesses. The review produced **6 findings** (1 Critical, 4 High, 1 Medium, 0 Low). Each finding was checked automatically to confirm that the quoted code exists in the reported file. AI-assisted findings should still be validated by a developer before being treated as confirmed vulnerabilities.

## 3. Findings Summary

| Severity | Count |
|---|---:|
| Critical | 1 |
| High | 4 |
| Medium | 1 |
| Low | 0 |
| **Total** | **6** |

| ID | Severity | File | Title |
|---|---|---|---|
| TF-001 | Critical | `supabase/functions/search-tasks/index.ts` | SQL Injection in task search |
| TF-002 | High | `supabase/functions/get-profile/index.ts` | Missing Authorization and Authentication Checks |
| TF-003 | High | `supabase/functions/update-task/index.ts` | Use of Privileged Service Role Client with Unverified User Input |
| TF-004 | High | `supabase/migrations/002_access_policies.sql` | Overly Permissive Task Select Policy |
| TF-005 | High | `supabase/migrations/002_access_policies.sql` | Insecure Task Comment Select Policy |
| TF-006 | Medium | `src/components/TaskComments.tsx` | Potential Cross-Site Scripting (XSS) via dangerouslySetInnerHTML |

## 4. Detailed Findings

### Finding TF-001: SQL Injection in task search

**Severity:** Critical  
**Category:** SQL Injection  
**CWE:** CWE-89  
**Confidence:** High  
**Affected File:** `supabase/functions/search-tasks/index.ts`  
**Code Location:** lines 20-28

#### Description

User input from the search query parameter 'q' is directly interpolated into a raw SQL query string without sanitization or parameterization, then executed via sql.unsafe().

#### Vulnerable Code

```
    const query = `
      SELECT id, title, description, status
      FROM public.tasks
      WHERE title ILIKE '%${searchTerm}%'
      ORDER BY created_at DESC
      LIMIT 25
    `;

    const tasks = await sql.unsafe(query);
```

#### Potential Impact

An attacker can execute arbitrary SQL commands, potentially leading to unauthorized data access, modification, or deletion across the database.

#### Recommended Fix

Use parameterized queries or prepared statements provided by the postgres library instead of string interpolation and sql.unsafe().

#### Secure Code Example

```
    const tasks = await sql`
      SELECT id, title, description, status
      FROM public.tasks
      WHERE title ILIKE ${'%' + searchTerm + '%'}
      ORDER BY created_at DESC
      LIMIT 25
    `;
```

#### Assumptions and Validation Notes

The underlying postgres library supports tagged template literals for safe parameterization.

### Finding TF-002: Missing Authorization and Authentication Checks

**Severity:** High  
**Category:** Broken Access Control  
**CWE:** CWE-862  
**Confidence:** High  
**Affected File:** `supabase/functions/get-profile/index.ts`  
**Code Location:** lines 23-26

#### Description

The edge function accepts an arbitrary 'userId' parameter via query string and queries the profiles table using the Supabase service role key, which bypasses Row Level Security (RLS). Furthermore, there is no validation to check if the caller is authenticated or authorized to view the profile of the requested 'userId'.

#### Vulnerable Code

```
    const supabase = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? ""
    );
```

#### Potential Impact

Any unauthorized user or unauthenticated attacker can query the endpoint with arbitrary user IDs and retrieve sensitive profile information for any user in the system.

#### Recommended Fix

Use the user's JWT from the Authorization header to create a scoped Supabase client (or validate the user's session) instead of using the service role key, or explicitly verify that the requesting user has permission to access the specified profile.

#### Secure Code Example

```
    const authHeader = request.headers.get("Authorization")!;
    const supabase = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_ANON_KEY") ?? "",
      { global: { headers: { Authorization: authHeader } } }
    );
```

#### Assumptions and Validation Notes

Assumes that profiles are meant to be restricted based on ownership or proper RLS policies, and service role usage should be limited to administrative operations.

### Finding TF-003: Use of Privileged Service Role Client with Unverified User Input

**Severity:** High  
**Category:** Broken Authorization / Improper Access Control  
**CWE:** CWE-284  
**Confidence:** High  
**Affected File:** `supabase/functions/update-task/index.ts`  
**Code Location:** lines 31-41

#### Description

The function initializes the Supabase client using the SUPABASE_SERVICE_ROLE_KEY, which bypasses Row Level Security (RLS). It then directly applies user-supplied updates (`changes`) and target identifiers (`taskId`) without verifying the calling user's authentication context, authorization, or ownership of the task.

#### Vulnerable Code

```
    const supabase = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? ""
    );

    const { data, error } = await supabase
      .from("tasks")
      .update(changes)
      .eq("id", taskId)
      .select()
      .single();
```

#### Potential Impact

Any unauthenticated or unauthorized user who can invoke this edge function can modify arbitrary fields on any task in the database, leading to potential data tampering or privilege escalation.

#### Recommended Fix

Pass the user's incoming Authorization header to the Supabase client creation instead of using the service role key, allowing RLS policies to enforce proper access control.

#### Secure Code Example

```
    const authHeader = request.headers.get("Authorization") ?? "";
    const supabase = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_ANON_KEY") ?? "",
      { global: { headers: { Authorization: authHeader } } }
    );
```

#### Assumptions and Validation Notes

Assumes that tasks are intended to be protected by RLS and user authorization, and that the function should not grant unrestricted administrative updates to arbitrary callers.

### Finding TF-004: Overly Permissive Task Select Policy

**Severity:** High  
**Category:** Missing Authorization / Access Control  
**CWE:** CWE-862  
**Confidence:** High  
**Affected File:** `supabase/migrations/002_access_policies.sql`  
**Code Location:** lines 34-38

#### Description

The SELECT policy on the tasks table allows any authenticated user to view all tasks regardless of whether they own the corresponding project or task.

#### Vulnerable Code

```
CREATE POLICY "Users can view tasks"
ON public.tasks
FOR SELECT
TO authenticated
USING (true);
```

#### Potential Impact

Any authenticated user can read sensitive task details across all projects and users, violating confidentiality.

#### Recommended Fix

Restrict the SELECT policy to ensure users can only view tasks belonging to projects they own or have access to.

#### Secure Code Example

```
CREATE POLICY "Users can view tasks"
ON public.tasks
FOR SELECT
TO authenticated
USING (EXISTS (SELECT 1 FROM public.projects WHERE projects.id = tasks.project_id AND projects.owner_id = auth.uid()));
```

#### Assumptions and Validation Notes

Assumes tasks should only be visible to project owners or authorized participants.

### Finding TF-005: Insecure Task Comment Select Policy

**Severity:** High  
**Category:** Missing Authorization / Access Control  
**CWE:** CWE-862  
**Confidence:** High  
**Affected File:** `supabase/migrations/002_access_policies.sql`  
**Code Location:** lines 53-63

#### Description

The policy allows any authenticated user to view comments for any task as long as the task exists, which leverages the overly permissive task visibility or simply verifies the existence of any task.

#### Vulnerable Code

```
CREATE POLICY "Users can view task comments"
ON public.task_comments
FOR SELECT
TO authenticated
USING (
  EXISTS (
    SELECT 1
    FROM public.tasks
    WHERE tasks.id = task_comments.task_id
  )
);

```

#### Potential Impact

Unauthorized users can read private comments on tasks they do not have access to.

#### Recommended Fix

Ensure the comment viewing policy verifies that the user has permission to view the parent task/project.

#### Secure Code Example

```
CREATE POLICY "Users can view task comments"
ON public.task_comments
FOR SELECT
TO authenticated
USING (
  EXISTS (
    SELECT 1
    FROM public.tasks
    JOIN public.projects ON projects.id = tasks.project_id
    WHERE tasks.id = task_comments.task_id
    AND projects.owner_id = auth.uid()
  )
);
```

#### Assumptions and Validation Notes

Assumes comments should follow the same access restrictions as the underlying tasks and projects.

### Finding TF-006: Potential Cross-Site Scripting (XSS) via dangerouslySetInnerHTML

**Severity:** Medium  
**Category:** Cross-Site Scripting  
**CWE:** CWE-79  
**Confidence:** Medium  
**Affected File:** `src/components/TaskComments.tsx`  
**Code Location:** lines 39-43

#### Description

The component renders comment text using React's dangerouslySetInnerHTML property. If comment.text originates from user input and is not properly sanitized on the server or client before being stored/rendered, this could lead to a Cross-Site Scripting (XSS) vulnerability.

#### Vulnerable Code

```
<div
                dangerouslySetInnerHTML={{
                  __html: comment.text,
                }}
              />
```

#### Potential Impact

An attacker could inject malicious scripts that execute in the context of other users' browsers when viewing comments, potentially leading to session hijacking or unauthorized actions.

#### Recommended Fix

Avoid using dangerouslySetInnerHTML for rendering user-supplied comments unless absolutely necessary. If HTML rendering is required, sanitize the input using a robust sanitization library like DOMPurify before passing it to dangerouslySetInnerHTML.

#### Secure Code Example

```
<div>{comment.text}</div>
```

#### Assumptions and Validation Notes

Assumes comment.text might contain unsanitized user-supplied HTML data if sanitization is not performed prior to this component.

## 5. Overall Assessment

The application shows significant potential weaknesses in access control and input handling. Address the Critical and High findings first, then work through the Medium and Low items.

## 6. Scope and Limitations

- Static code review only; no exploit execution or runtime testing
- AI output can be incomplete or wrong, so some findings need manual confirmation
- No guarantee that every vulnerability was found
- Impact statements assume the endpoint can be reached by the stated caller. Whether a login is required before an edge function runs (platform or gateway settings) is not visible in the code
- Exploitability depends on deployment context that is not visible in the code
