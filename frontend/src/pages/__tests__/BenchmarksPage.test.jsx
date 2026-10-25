import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { describe, expect, it, vi } from 'vitest'
import BenchmarksPage from '../BenchmarksPage'

vi.mock('../../contexts/AuthContext', () => ({
  useAuth: () => ({ loginWithGitHub: vi.fn(), user: null }),
}))

vi.mock('../../components/Header', () => ({ default: () => <div>Header</div> }))
vi.mock('../../components/Footer', () => ({ default: () => <div>Footer</div> }))

describe('BenchmarksPage', () => {
  it('publishes measured results and their limits', () => {
    render(
      <MemoryRouter>
        <BenchmarksPage />
      </MemoryRouter>
    )

    expect(screen.getByText('97%')).toBeInTheDocument()
    expect(screen.getByText('58%')).toBeInTheDocument()
    expect(screen.getByText('171')).toBeInTheDocument()
    expect(screen.getByText('8')).toBeInTheDocument()
    expect(screen.getByText(/Legacy unvalidated.*not a quality claim/i)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /Rule-quality gate methodology/i })).toHaveAttribute(
      'href',
      expect.stringContaining('benchmarks/rule-quality/README.md')
    )
  })
})
