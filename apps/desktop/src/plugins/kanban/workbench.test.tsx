import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

// The harness performs the locale registration normally owned by plugin load.
// eslint-disable-next-line no-restricted-imports
import { registerPluginLocales } from '@/i18n/plugin-i18n'

import type * as KanbanApi from './api'
import { $boardSlug, confirmMission, fetchDelivery, fetchWorkbench, previewMission, respondToDecision } from './api'
import { MissionWorkbench } from './workbench'
import { WORKBENCH_LOCALES } from './workbench-i18n'
import type { DeliverySnapshot, MissionPlan, WorkbenchSnapshot } from './workbench-types'

vi.mock('./board-switcher', () => ({ BoardSwitcher: () => <span>Test board</span> }))
vi.mock('./api', async importOriginal => ({
  ...(await importOriginal<typeof KanbanApi>()),
  confirmMission: vi.fn(),
  fetchDelivery: vi.fn(),
  fetchWorkbench: vi.fn(),
  previewMission: vi.fn(),
  respondToDecision: vi.fn()
}))

const snapshot = (): WorkbenchSnapshot => ({
  fetched_at: 1000,
  board: { slug: 'work', title: 'Work', project_id: null },
  projects: [
    { id: 'a', name: 'Project A' },
    { id: 'b', name: 'Project B' }
  ],
  tasks: [
    {
      id: 'root',
      title: 'Improve project',
      body: 'Accepted goal',
      status: 'triage',
      root_id: 'root',
      relationship_state: 'ROOT'
    },
    { id: 'item', title: 'Write the regression', status: 'triage', root_id: 'root', relationship_state: 'WORK_ITEM' },
    { id: 'legacy', title: 'Legacy task', status: 'blocked', root_id: null, relationship_state: 'UNKNOWN' }
  ],
  runs: [],
  activity: [],
  decisions: [],
  execution: { state: 'paused', reason: 'Execution is paused' },
  unknowns: ['Legacy origin unavailable']
})

const delivery = (): DeliverySnapshot => ({
  fetched_at: 1000,
  url: null,
  repo: null,
  number: null,
  head: null,
  base: null,
  draft: null,
  state: 'UNKNOWN',
  ci: { state: 'unknown', checks: [] },
  review: { state: 'unknown', entries: [] },
  files: [],
  unknowns: ['No delivery reference'],
  waiting_for_human_merge: false
})

const plan: MissionPlan = {
  title: 'Verify offline behavior',
  body: 'Acceptance: all relevant checks pass',
  work_items: [{ title: 'Add regression', body: 'Use a disposable project' }],
  assumptions: ['No production access'],
  model: 'test-provider',
  status: 'preview'
}

let dispose = () => {}
beforeEach(() => {
  vi.resetAllMocks()
  $boardSlug.set('work')
  dispose = registerPluginLocales('kanban', WORKBENCH_LOCALES)
  vi.mocked(fetchWorkbench).mockImplementation(async () => snapshot())
  vi.mocked(fetchDelivery).mockImplementation(async () => delivery())
  vi.mocked(previewMission).mockResolvedValue(plan)
  vi.mocked(confirmMission).mockResolvedValue({
    root_id: 'new-root',
    work_item_ids: ['new-item'],
    replayed: false,
    execution: { state: 'paused', reason: 'Paused' }
  })
  vi.mocked(respondToDecision).mockResolvedValue({})
})
afterEach(() => {
  cleanup()
  dispose()
  $boardSlug.set('')
})

function mount() {
  return render(
    <QueryClientProvider
      client={new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })}
    >
      <MissionWorkbench />
    </QueryClientProvider>
  )
}

describe('Mission Workbench', () => {
  it('shows original authored worklog only for the selected Mission', async () => {
    vi.mocked(fetchWorkbench).mockResolvedValue({
      ...snapshot(),
      comments: [
        {
          id: 1,
          task_id: 'item',
          author: 'codex',
          body: 'Reported test failure: widget creation returns 500.',
          created_at: 1000
        },
        {
          id: 2,
          task_id: 'item',
          author: 'claude',
          body: 'Review note: reproduce before changing the handler.',
          created_at: 1001
        },
        { id: 3, task_id: 'legacy', author: 'other-agent', body: 'Another Mission worklog', created_at: 1002 }
      ]
    })
    mount()
    await screen.findByText('Reported test failure: widget creation returns 500.')
    expect(screen.getByText('Review note: reproduce before changing the handler.')).toBeTruthy()
    expect(screen.queryByText('Another Mission worklog')).toBeNull()
    expect(screen.getByText('No recorded execution. Agent activity is unknown.')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: /Legacy task/ }))
    expect(screen.getByText('Another Mission worklog')).toBeTruthy()
    expect(screen.queryByText('Reported test failure: widget creation returns 500.')).toBeNull()
  })

  it('presents canonical Mission membership and missing execution honestly', async () => {
    const data = snapshot()
    data.tasks.reverse()
    vi.mocked(fetchWorkbench).mockResolvedValue(data)
    mount()
    expect(await screen.findByRole('heading', { name: 'Improve project' })).toBeTruthy()
    expect(screen.getByText('Workbench does not dispatch execution')).toBeTruthy()
    expect(screen.getByText('No recorded execution. Agent activity is unknown.')).toBeTruthy()
    expect(screen.getByRole('button', { name: /Write the regression/ })).toBeTruthy()
    expect(screen.queryByText('Waiting for Human Merge')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: /Legacy task/ }))
    expect(screen.getByText(/this task has not been attached by inference/)).toBeTruthy()
    expect(confirmMission).not.toHaveBeenCalled()
  })

  it('requires AI preview and explicit confirmation, with the same request identity on uncertain retry', async () => {
    vi.mocked(confirmMission).mockRejectedValueOnce(new Error('response lost'))
    mount()
    await screen.findByText('Accepted goal')
    fireEvent.change(screen.getByRole('textbox', { name: 'What would you like to achieve?' }), {
      target: { value: 'Improve the offline checks' }
    })
    fireEvent.click(screen.getByRole('button', { name: 'Preview AI plan' }))
    await screen.findByDisplayValue('Verify offline behavior')
    expect(confirmMission).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Confirm and save Mission' }))
    await screen.findByRole('alert')
    fireEvent.click(screen.getByRole('button', { name: 'Confirm and save Mission' }))
    await screen.findByText(/Mission saved/)
    expect(vi.mocked(confirmMission).mock.calls).toHaveLength(2)
    expect(vi.mocked(confirmMission).mock.calls[0]).toEqual(vi.mocked(confirmMission).mock.calls[1])
    expect(vi.mocked(confirmMission).mock.calls[0][2]).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Plan another Mission' }))
    expect(screen.getByRole('textbox', { name: 'What would you like to achieve?' })).toHaveProperty('disabled', false)
    expect(screen.queryByRole('button', { name: 'Confirm and save Mission' })).toBeNull()
  })

  it('does not fabricate a plan or enable confirmation when the model is unavailable', async () => {
    vi.mocked(previewMission).mockResolvedValue({ ...plan, status: 'unavailable', work_items: [] })
    mount()
    await screen.findByText('Accepted goal')
    fireEvent.change(screen.getByRole('textbox', { name: 'What would you like to achieve?' }), {
      target: { value: 'A goal' }
    })
    fireEvent.click(screen.getByRole('button', { name: 'Preview AI plan' }))
    await screen.findByText(/AI planning is unavailable/)
    expect(screen.queryByRole('button', { name: 'Confirm and save Mission' })).toBeNull()
    expect(confirmMission).not.toHaveBeenCalled()
  })

  it('drops a preview when changing project rather than confirming it into the new scope', async () => {
    mount()
    await screen.findByText('Accepted goal')
    fireEvent.change(screen.getByRole('textbox', { name: 'What would you like to achieve?' }), {
      target: { value: 'A goal' }
    })
    fireEvent.click(screen.getByRole('button', { name: 'Preview AI plan' }))
    await screen.findByDisplayValue('Verify offline behavior')
    fireEvent.change(screen.getByRole('combobox', { name: 'Project' }), { target: { value: 'b' } })
    await waitFor(() => expect(fetchWorkbench).toHaveBeenLastCalledWith('b'))
    expect(screen.queryByRole('button', { name: 'Confirm and save Mission' })).toBeNull()
    expect(confirmMission).not.toHaveBeenCalled()
  })

  it('shows actual review and CI state without treating an open Draft as a completed delivery', async () => {
    vi.mocked(fetchDelivery).mockResolvedValue({
      ...delivery(),
      url: 'https://github.com/example/project/pull/8',
      repo: 'example/project',
      number: 8,
      state: 'OPEN',
      draft: true,
      head: 'a'.repeat(40),
      ci: { state: 'pending', checks: [{ name: 'Required check', status: 'queued' }] },
      files: [{ path: 'app.py', additions: 3, deletions: 1 }]
    })
    mount()
    const center = await screen.findByRole('region', { name: 'Delivery center' })
    await within(center).findByText('example/project #8')
    expect(within(center).getByText(/Draft PR/)).toBeTruthy()
    expect(within(center).getByText('pending')).toBeTruthy()
    expect(within(center).getByText('app.py')).toBeTruthy()
    expect(within(center).queryByText('Waiting for Human Merge')).toBeNull()
  })

  it('records an explicit Human response and retains the distinction from dispatch authority', async () => {
    vi.mocked(fetchWorkbench).mockResolvedValue({
      ...snapshot(),
      decisions: [
        {
          id: 'event:20',
          task_id: 'item',
          title: 'Choose compatibility behavior',
          reason: 'Two valid behaviors affect callers',
          recommendation: 'Keep compatibility',
          status: 'pending',
          history: []
        }
      ]
    })
    mount()
    await screen.findByText(/Choose compatibility behavior/)
    fireEvent.change(screen.getByRole('textbox', { name: 'Decision response' }), {
      target: { value: 'Keep compatibility' }
    })
    fireEvent.click(screen.getByRole('button', { name: 'Record decision' }))
    await screen.findByText('Decision recorded in the task history.')
    expect(respondToDecision).toHaveBeenCalledWith('item', 'event:20', 'Keep compatibility')
    expect(screen.getByText(/does not unblock or start execution/)).toBeTruthy()
    expect(confirmMission).not.toHaveBeenCalled()
  })
})
