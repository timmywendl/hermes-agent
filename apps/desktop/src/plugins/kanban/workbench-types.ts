import type { KanbanEvent, KanbanRun, KanbanTaskFull } from './types'

export interface WorkbenchTask extends KanbanTaskFull {
  project_id?: null | string
  root_id: null | string
  relationship_state: 'ROOT' | 'UNKNOWN' | 'WORK_ITEM'
}

export interface WorkbenchDecision {
  id: string
  task_id: string
  title: string
  reason: string
  recommendation: null | string
  status: string
  history: { body: string; created_at: number; author?: string }[]
}

export interface WorkbenchSnapshot {
  fetched_at: number | string
  board: { slug: string; title: string; project_id: null | string }
  projects: { id: string; name: string; description?: string; primary_path?: string }[]
  tasks: WorkbenchTask[]
  runs: (KanbanRun & { task_id: string; custody_state?: string })[]
  activity: (KanbanEvent & { task_id: string })[]
  decisions: WorkbenchDecision[]
  execution: { state: string; reason: string }
  unknowns: string[]
}

export interface MissionPlan {
  title: string
  body: string
  work_items: { title: string; body: string }[]
  assumptions: string[]
  model: null | string
  status: 'preview' | 'unavailable'
  reason?: string
}

export interface MissionConfirmation {
  root_id: string
  work_item_ids: string[]
  replayed: boolean
  execution: { state: string; reason: string }
}

export interface DeliverySnapshot {
  fetched_at: number | string
  url: null | string
  repo: null | string
  number: null | number
  head: null | string
  base: null | string
  draft: null | boolean
  state: string
  ci: { state: string; checks: { name: string; status?: string; state?: string; conclusion?: null | string }[] }
  review: { state: string; entries: { author?: string; state: string; head?: string; head_sha?: string }[] }
  files: { path: string; additions: number; deletions: number }[]
  unknowns: string[]
  waiting_for_human_merge: boolean
}
