# PyJWT Refactoring Plan (Revised)

Three-person refactor. Each member owns a distinct module set and ships changes
as small, independently revertable PRs. All refactors must preserve external
behavior — the public `jwt.encode` / `jwt.decode` surface and all exception
types stay identical.

**Baseline before any work:** `pytest tests/` → 163 passed (api_jws + api_jwt
suites) on a machine without the `cryptography` extra. Full suite must stay
green after every PR.

---

## Part 1 — Core JWT/JWS API (Member A)

**Modules:** `jwt/api_jws.py`, `jwt/api_jwt.py`, `jwt/warnings.py`

**Goal:** Cut duplication in the encode/decode paths and split the long
`encode` methods into named pieces. Do **not** touch `help.py` (unrelated),
do **not** inline the small `_validate_*` helpers (they're fine), and do
**not** convert any `return` codes to exceptions (no such patterns exist
in this scope).

### Tasks

1. **Deduplicate the `RemovedInPyjwt3Warning` kwargs warning.**
   The same 7-line block is copy-pasted four times
   (`api_jws.py:219`, `api_jws.py:270`, `api_jwt.py:231`, `api_jwt.py:357`).
   Add `_warn_removed_kwargs(kwargs, func_name)` to `warnings.py` and replace
   all four call sites. Also fold in the `verify` legacy-kwarg mismatch
   warning at `api_jwt.py:248` if it fits.

2. **Split `PyJWS.encode` (~88 lines → ~30).** Extract:
   - `_resolve_algorithm(algorithm, key, headers) -> tuple[str, bool]`
     — returns `(algorithm_name, is_payload_detached)`. Owns the
     `_ALGORITHM_UNSET` / `None` / `PyJWK` / `headers["alg"]` / `headers["b64"]`
     juggling currently at lines 132–155.
   - `_build_header(algorithm_name, headers, is_payload_detached) -> dict`
     — owns lines 156–170.
   - `_prepare_signing_key(alg_obj, key) -> Any` — owns the PyJWK unwrap +
     `prepare_key` + `check_key_length` block. Reuse this from
     `_verify_signature` so the key-length warn-or-raise logic lives in
     one place.

3. **Split `PyJWT.encode`.** Extract `_prepare_payload_claims(payload) -> dict`
   covering the datetime→epoch conversion and `iss` type check
   (`api_jwt.py:124–139`).

4. **Verification.** Run the full test suite after each of (1)–(3). Each
   change ships as its own PR so any can be reverted alone.

### Out of scope for Part 1
- `help.py` (it's a `python -m jwt` info dump, irrelevant here)
- Inlining `_validate_kid` / `_validate_crit` / `_validate_iat` etc.
- New error-handling semantics. All exceptions raised today must still be
  raised, with the same messages, in the same order.

---

## Part 2 — Algorithm Implementations (Member B)

**Module:** `jwt/algorithms.py` (~1000 lines)

**Goal:** Reduce duplication across HMAC / RSA / EC / Ed / PSS algorithm
classes. Make adding a new algorithm easier without changing crypto
semantics.

### Tasks

1. **Audit duplication first.** Before editing, list every place
   `isinstance(key, ...)` checks recur in `prepare_key`, `sign`, `verify`,
   `to_jwk`, and `from_jwk` across the algorithm classes. Share that list
   with Members A and C as the work plan.

2. **Centralize key-type validation.** Add a private `_check_key_type(key,
   expected_types, alg_name)` helper at module scope (or on the `Algorithm`
   base class) that raises `InvalidKeyError` with a consistent message.
   Replace the per-class isinstance branches.

3. **Factor JWK conversion.** `to_jwk` / `from_jwk` for RSA and EC share
   structural patterns (curve name → params, base64url-encode big-int
   coordinates). Extract shared helpers — start with the int-to-base64url
   round trip currently re-implemented in each class.

4. **Do not touch crypto primitives.** `sign` / `verify` calls into
   `cryptography` stay byte-for-byte identical. Any structural change must
   be validated with the existing test vectors in `tests/test_algorithms.py`.

5. **One PR per algorithm family** (HMAC, RSA, EC, Ed, PSS). Each PR runs
   the full `tests/test_algorithms.py` (1623 tests) green before merging.

### Out of scope for Part 2
- Adding new algorithms.
- Replacing the `cryptography` dependency.
- Changing `Algorithm`'s public method signatures.

---

## Part 3 — JWK / JWKS and Utilities (Member C)

**Modules:** `jwt/api_jwk.py`, `jwt/jwks_client.py`, `jwt/jwk_set_cache.py`,
`jwt/utils.py`, `jwt/types.py`

**Goal:** Tighten key-management code paths and remove utility cruft.

### Tasks

1. **Consolidate `PyJWKClientError` paths.** Today errors from URL fetch,
   JSON parse, and "kid not found" raise the same exception class with
   different messages. Audit — if any path raises a bare `Exception` or
   leaks a `urllib` error, wrap it.

2. **Decide `PyJWKSet`'s shape.** If it's only ever used as
   `jwk_set.keys[idx]`, inline it. If it carries real behavior (kid lookup,
   filtering), keep it but move kid-lookup off `PyJWKClient` onto
   `PyJWKSet`.

3. **Audit `utils.py`.** Anything that's now a one-liner over the stdlib
   (e.g. base64url) should be inlined at call sites or deleted. Do not add
   new abstractions.

4. **Type aliases in `types.py`.** Verify every alias is still referenced.
   Delete unused ones. Do not rename existing aliases — that breaks
   downstream type checkers.

5. **JWKS caching tests.** `tests/test_jwks_client.py` (390 lines) already
   covers the network paths; add tests only if a refactor introduces a
   branch the existing suite doesn't cover.

### Out of scope for Part 3
- Adding async support.
- Changing the JWKS HTTP client (still `urllib`).

---

## Coordination

- **Branch naming:** `refactor/api-<member>` per PR.
- **Merge order:** Part 1's `_prepare_signing_key` extraction touches code
  that calls into `Algorithm.check_key_length`; if Part 2 changes that
  method's signature, Part 1 merges first.
- **Shared check before each PR:** `pytest tests/ -q` and `ruff check jwt/`.
- **Rollback:** every PR is a single logical change. Reverting any one PR
  must leave the suite green.
