# Pushing CERBERUS to your repo

CERBERUS has NOT been pushed. Here's how to do it yourself, or how to let
me do it (you'll need to provide a GitHub Personal Access Token).

## Option A — You push it (recommended)

```bash
# 1. Unpack the cerberus.tar.gz into your repo
cd /path/to/ambiqhal_ambiq
tar xzf ~/Downloads/cerberus.tar.gz       # creates cerberus/

# 2. Create a branch
git checkout ambiq-stable
git pull
git checkout -b cerberus-guard-integration

# 3. Stage and commit
git add cerberus/ .github/workflows/cerberus.yml
git commit -m "Add CERBERUS G.U.A.R.D. static analysis pipeline

Three-headed C analysis: deterministic scanner (94 checks) + MISRA C:2012
/ CERT C catalog + AI deep analysis + Unity test generation, with an
intent layer and a convergence loop for cross-head consensus.

Runs on PR via .github/workflows/cerberus.yml."

# 4. Push
git push -u origin cerberus-guard-integration

# 5. Open a PR on GitHub from cerberus-guard-integration -> ambiq-stable
```

## Option B — I push it for you

I need a GitHub PAT with `repo` scope. Generate one at:
  GitHub -> Settings -> Developer settings -> Personal access tokens
  -> Fine-grained tokens -> generate, scope it to ambiqhal_ambiq, repo write.

Then paste it and say "push it". I will:
  1. Clone ambiqhal_ambiq (ambiq-stable branch)
  2. Branch cerberus-guard-integration
  3. Copy in the cerberus/ tree + workflow
  4. Commit and push
  5. Give you the PR link

Note: a PAT pasted into chat is a live credential. Prefer Option A if you
want to keep it off the wire. If you do paste one, rotate/revoke it after.
