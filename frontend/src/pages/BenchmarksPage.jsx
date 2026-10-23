import { ExternalLink } from 'lucide-react'
import { useAuth } from '../contexts/AuthContext'
import Header from '../components/Header'
import Footer from '../components/Footer'
import CtaPair from '../components/CtaPair'

const repositoryBase = 'https://github.com/aicodesentry/mitig8it/blob/main'

const metrics = [
  {
    value: '97%',
    label: 'posted-finding precision',
    detail: 'Measured on the September 2026 labelled vulnerable-repository corpus.',
  },
  {
    value: '58%',
    label: 'vulnerable-corpus recall',
    detail: 'Coverage remains incomplete; a clean review is not proof that a pull request is safe.',
  },
  {
    value: '171',
    label: 'labelled vulnerabilities',
    detail: 'Across 23 public JavaScript, TypeScript, Python, and template repositories.',
  },
  {
    value: '8',
    label: 'candidate fixes executed end to end',
    detail: 'This is a small validation sample, so fix effectiveness is not generalized beyond it.',
  },
]

const ruleInventory = [
  { value: '0', label: 'rules validated to the current statistical gate' },
  { value: '201', label: 'legacy rules allowed only under an explicit unvalidated exception' },
  { value: '14', label: 'quarantined rules withheld from posting' },
]

const evidenceLinks = [
  {
    label: 'Vulnerable corpus and failure analysis',
    href: `${repositoryBase}/docs/validation/vulnerable-corpus-2026-09.md`,
  },
  {
    label: 'Production-readiness evidence ledger',
    href: `${repositoryBase}/docs/production-readiness.md`,
  },
  {
    label: 'Rule-quality gate methodology',
    href: `${repositoryBase}/benchmarks/rule-quality/README.md`,
  },
]

export default function BenchmarksPage() {
  const { loginWithGitHub, user } = useAuth()

  return (
    <div className="min-h-screen bg-neutral-950 text-white">
      <Header />
      <main>
        <section className="border-b border-neutral-800/60">
          <div className="mx-auto max-w-6xl px-4 py-16 sm:px-6 sm:py-20 lg:px-8">
            <p className="text-xs font-semibold uppercase tracking-[0.2em] text-emerald-300">
              Benchmarks · last measured September 2026
            </p>
            <h1 className="mt-4 max-w-3xl text-3xl font-bold tracking-tight sm:text-5xl">
              Measured signal, including the uncomfortable parts
            </h1>
            <p className="mt-5 max-w-3xl text-base leading-7 text-neutral-300">
              These results describe a labelled public-repository evaluation, not a guarantee for
              arbitrary code. Precision is promising; recall, fix coverage, and statistical rule
              validation still need work.
            </p>
          </div>
        </section>

        <section aria-labelledby="corpus-results" className="mx-auto max-w-6xl px-4 py-14 sm:px-6 lg:px-8">
          <h2 id="corpus-results" className="text-2xl font-semibold tracking-tight">
            Vulnerable-repository corpus
          </h2>
          <div className="mt-7 grid gap-px overflow-hidden rounded-2xl border border-neutral-800 bg-neutral-800 sm:grid-cols-2 lg:grid-cols-4">
            {metrics.map((metric) => (
              <article key={metric.label} className="bg-neutral-950 p-5">
                <p className="text-3xl font-semibold text-emerald-300">{metric.value}</p>
                <h3 className="mt-2 text-sm font-semibold text-white">{metric.label}</h3>
                <p className="mt-2 text-sm leading-6 text-neutral-400">{metric.detail}</p>
              </article>
            ))}
          </div>
        </section>

        <section className="border-y border-neutral-800 bg-neutral-900/30">
          <div className="mx-auto max-w-6xl px-4 py-14 sm:px-6 lg:px-8">
            <div className="max-w-3xl">
              <h2 className="text-2xl font-semibold tracking-tight">Current rule-release gate</h2>
              <p className="mt-3 text-sm leading-6 text-neutral-300">
                A new, changed, or re-enabled rule must have at least 100 reviewed holdout
                predictions, no unresolved labels, and a two-sided 95% Wilson precision lower bound
                of at least 95%. Missing or stale evidence blocks the rule.
              </p>
            </div>
            <dl className="mt-7 grid gap-4 md:grid-cols-3">
              {ruleInventory.map((item) => (
                <div key={item.label} className="rounded-xl border border-neutral-800 bg-neutral-950 p-5">
                  <dt className="text-sm leading-6 text-neutral-400">{item.label}</dt>
                  <dd className="order-first text-3xl font-semibold text-white">{item.value}</dd>
                </div>
              ))}
            </dl>
            <p className="mt-5 max-w-3xl text-sm leading-6 text-amber-200">
              “Legacy unvalidated” is a compatibility state, not a quality claim. Production
              readiness remains blocked until active rules are supported by current holdout evidence.
            </p>
          </div>
        </section>

        <section className="mx-auto max-w-6xl px-4 py-14 sm:px-6 lg:px-8">
          <h2 className="text-2xl font-semibold tracking-tight">Inspect the evidence</h2>
          <p className="mt-3 max-w-3xl text-sm leading-6 text-neutral-400">
            The repository records fixtures, exclusions, failure modes, and release criteria so the
            headline numbers can be challenged and reproduced.
          </p>
          <ul className="mt-6 grid gap-3 md:grid-cols-3">
            {evidenceLinks.map((item) => (
              <li key={item.href}>
                <a
                  href={item.href}
                  target="_blank"
                  rel="noreferrer"
                  className="flex h-full items-center justify-between gap-4 rounded-xl border border-neutral-800 bg-neutral-900 px-5 py-4 text-sm font-medium text-neutral-200 transition hover:border-neutral-600 hover:text-white"
                >
                  {item.label}
                  <ExternalLink className="h-4 w-4 shrink-0" aria-hidden="true" />
                </a>
              </li>
            ))}
          </ul>
        </section>

        <section className="mx-auto max-w-6xl px-4 pb-20 sm:px-6 sm:pb-24 lg:px-8">
          <div className="rounded-2xl border border-neutral-800 bg-neutral-900 px-6 py-12 text-center sm:px-16">
            <h2 className="text-2xl font-semibold tracking-tight">Evaluate it on one repository</h2>
            <p className="mx-auto mt-3 max-w-xl text-sm leading-6 text-neutral-400">
              Compare the review against your own labelled findings. Treat abstentions and misses as
              part of the result, not as invisible successes.
            </p>
            <div className="mt-7">
              <CtaPair user={user} onLogin={loginWithGitHub} />
            </div>
          </div>
        </section>
      </main>
      <Footer />
    </div>
  )
}
