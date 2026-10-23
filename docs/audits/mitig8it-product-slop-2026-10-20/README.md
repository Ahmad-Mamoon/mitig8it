# Mitig8it product audit — 2026-10-20

## Verdict

Mitig8it has a credible core idea: security findings appear in the pull request and some fixes are backed by execution evidence. The product feels like slop because the interface presents a broad, finished SaaS while the repository still contains fake, dead, contradictory, and unfinished surfaces. The gap between what the product says and what it can currently prove is larger than the visual-polish gap.

## Captured steps

1. **Desktop homepage — mixed.** The value proposition and pull-request example are clear. The page overstates the verification coverage, uses low-contrast secondary text, and follows a repetitive dark-card marketing pattern.
2. **Mobile homepage — broken.** At a 390px viewport, the sign-in control, headline, trust line, review example, caption, and commit button overflow horizontally.
3. **Sample review — mixed.** This is the best product proof, but the same synthetic review is immediately followed by a screenshot that makes the first artifact feel redundant. The page does not explain coverage, failure, or abstention rates.
4. **Security page — mixed.** It is unusually candid about the development-grade sandbox and static assertions, but this honesty contradicts the homepage's blanket claim that each fix is proven by a regression test.
5. **GitHub authorization — healthy handoff, weak brand.** OAuth works and clearly names Mitig8it. The app mark is an unreadably small wordmark inside a black square.
6. **Benchmarks page — poor.** A page named “Benchmarks” lists things that should be measured but publishes no values, methodology, dates, or links to the repository's real benchmark evidence.
7. **Customers page — poor.** A page named “Customers” contains audience hypotheses, not customers, logos, quotes, deployments, or outcomes.

## Why it reads as slop

### 1. Product truth is inconsistent

The homepage says every pull request gets exploitable findings, every fix is proven, and every verified fix is backed by a generated regression test. The security page and README say some fixes are only statically asserted, every executed candidate is development-unverified, recall is roughly 0.40–0.58, and only 8 fixes were executed end to end on real vulnerable code. The candid material is good; the unqualified homepage makes it look untrustworthy.

### 2. The navigation advertises fiction

The signed-in navigation exposes Code Playground, Subscription, Support, and Profile. Current source shows hardcoded plans with inert upgrade/contact buttons, a support form that reports success without sending anything, notification switches that only mutate local state, and a Delete Account button with no handler. Suppressions and Settings exist as routes but are missing from the navigation. This is the strongest source of “generated SaaS shell” feeling.

### 3. Proof pages contain labels instead of proof

“Benchmarks” has no benchmark results even though the repository has unusually strong measurement documents. “Customers” has no customers. These pages should either publish evidence or not exist.

### 4. The visual system is coherent but generic

Dark background, green accent, rounded bordered cards, Lucide icons, eyebrow labels, and repeated CTA panels are applied consistently. They do not create a distinct product identity, and the same card grammar is used whether the content is evidence, marketing, navigation, or a placeholder. The interface looks assembled from a SaaS starter rather than edited around the product's actual strengths.

### 5. Responsive and accessibility details were not finished

The public homepage visibly overflows at 390px. The dashboard sidebar is hidden below the `lg` breakpoint with no mobile replacement. Several small `neutral-500` labels on `neutral-950` are about 4.18:1, below WCAG AA's 4.5:1 requirement for normal text; `neutral-600` falls to about 2.53:1. Many custom buttons and links define hover states but no visible focus state. Profile switches have no accessible name or programmatic checked state.

## Highest-impact changes

1. Remove or feature-gate every fake signed-in surface: Subscription, Support form, notification preferences, Delete Account, and Code Playground. Put Suppressions and Settings in the navigation if they are real.
2. Rewrite the promise around what is measurably true: “high-confidence findings; executable fixes when Mitig8it can prove them; explicit abstention otherwise.”
3. Replace the empty Benchmarks page with the actual precision, recall, action-trial, and verified-fix numbers already in `README.md`; remove Customers until there is customer evidence.
4. Fix mobile overflow and add a mobile dashboard navigation before adding more visual polish.
5. Make the real GitHub review the primary proof object, then show failure/abstention states and a short explanation of the evidence level.

## Evidence limits

The live public pages and GitHub OAuth handoff were captured on 2026-10-20. The authenticated dashboard could not be entered without a GitHub account, so dashboard findings are based on the current checked-out implementation rather than captured authenticated screens. Keyboard behavior, screen-reader output, zoom reflow, and end-to-end remediation behavior were not tested. No claim of WCAG compliance is made.

## Implemented after this audit

The screenshots above remain the before-state evidence. The follow-up implementation:

- rewrote blanket verification claims around high-confidence findings, evidence levels,
  and explicit abstention;
- replaced the empty benchmarks page with measured precision, recall, corpus, and
  end-to-end-fix counts plus links to the underlying evidence;
- removed the fictional Customers page and redirected `/customers` to `/examples`;
- removed the inert Subscription, Support, Profile, and Playground routes from the
  shipped product surface while retaining real Settings and Suppressions navigation;
- added visible global keyboard focus treatment, raised low-contrast public text, made
  the review diff visible on first paint, and fixed the dashboard's mobile navigation;
- verified no horizontal overflow on `/`, `/benchmarks`, and `/examples` at 320, 390,
  768, and 1440 pixels, and passed the full frontend test, lint, and production build.

This improves product honesty and usability; it does not convert missing production
evidence into proof. The machine-readable production gate remains intentionally closed.
