import './workbench.css'

import { Button, host, useQuery, useQueryClient, useValue } from '@hermes/plugin-sdk'
import { useState } from 'react'

import { $boardSlug, fetchWorkbench, useKanbanScope } from './api'
import { BoardSwitcher } from './board-switcher'
import { AgentActivity, DecisionInbox, DeliveryCenter, SourceUnknowns } from './workbench-evidence'
import { useWorkbenchText } from './workbench-i18n'
import { GoalIntake, ProjectFacts } from './workbench-intake'
import type { WorkbenchSnapshot, WorkbenchTask } from './workbench-types'
import { missionDescription, workbenchTime } from './workbench-view'

function TaskChoice({ task, selected, onClick }: { task: WorkbenchTask; selected: boolean; onClick: () => void }) {
  const t = useWorkbenchText()

  return (
    <button aria-pressed={selected} className="workbench-task" onClick={onClick} type="button">
      <strong>{task.title}</strong>
      <span>
        {task.status} · {task.assignee || t('unknown')}
      </span>
    </button>
  )
}

function ProjectPicker({
  snapshot,
  projectId,
  onChange
}: {
  snapshot: WorkbenchSnapshot | undefined
  projectId: string
  onChange: (value: string) => void
}) {
  const t = useWorkbenchText()

  return (
    <section className="workbench-section">
      <label htmlFor="workbench-project">{t('project')}</label>
      <select id="workbench-project" onChange={event => onChange(event.target.value)} value={projectId}>
        <option value="">{t('allProjects')}</option>
        {snapshot?.projects.map(project => (
          <option key={project.id} value={project.id}>
            {project.name}
          </option>
        ))}
      </select>
      {snapshot?.projects.length === 0 && <p>{t('noProjects')}</p>}
      {snapshot?.projects
        .filter(project => project.id === projectId)
        .map(project => (
          <div key={project.id}>
            <p>{project.description}</p>
            <small>{project.primary_path}</small>
          </div>
        ))}
      {projectId && snapshot && <ProjectFacts context={snapshot.project_context} />}
    </section>
  )
}

function WorkbenchScope({ scope, slug }: { scope: string; slug: string }) {
  const t = useWorkbenchText()
  const client = useQueryClient()
  const [projectId, setProjectId] = useState('')
  const [selectedId, setSelectedId] = useState('')
  const queryKey = ['kanban', 'workbench', scope, slug, projectId]

  const query = useQuery({
    queryKey,
    queryFn: () => fetchWorkbench(projectId),
    retry: false,
    refetchInterval: 60_000
  })

  const snapshot = query.data
  const tasks = snapshot?.tasks ?? []

  const selected =
    tasks.find(task => task.id === selectedId) ?? tasks.find(task => task.relationship_state === 'ROOT') ?? tasks[0]

  const rootId = selected?.root_id ?? selected?.id
  const related = tasks.filter(task => task.id === rootId || (rootId && task.root_id === rootId))
  const taskIds = new Set(related.map(task => task.id))
  const roots = tasks.filter(task => task.relationship_state === 'ROOT')
  const unlinked = tasks.filter(task => task.relationship_state === 'UNKNOWN')

  const refresh = () => {
    void client.invalidateQueries({ queryKey })
  }

  return (
    <main className="workbench">
      <header className="workbench-header">
        <div>
          <h1>{t('title')}</h1>
          <p>{t('subtitle')}</p>
        </div>
        <BoardSwitcher />
        <Button onClick={() => host.navigate('/kanban')} variant="ghost">
          {t('board')}
        </Button>
        <Button disabled={query.isFetching} onClick={() => void query.refetch()} variant="outline">
          {t('refresh')}
        </Button>
      </header>
      <div className="workbench-pause" role="status">
        <strong>{t('paused')}</strong>
        <p>{t('pauseDetail')}</p>
      </div>
      {query.isError && <p role="alert">{snapshot ? t('stale') : t('unavailable')}</p>}
      {query.isPending && <p role="status">{t('unknown')}</p>}
      <div className="workbench-layout">
        <aside>
          <ProjectPicker
            onChange={value => {
              setProjectId(value)
              setSelectedId('')
            }}
            projectId={projectId}
            snapshot={snapshot}
          />
          <section className="workbench-section">
            <h2>{t('missions')}</h2>
            {roots.map(task => (
              <TaskChoice
                key={task.id}
                onClick={() => setSelectedId(task.id)}
                selected={rootId === task.id}
                task={task}
              />
            ))}
            {unlinked.length > 0 && <h3>{t('unlinked')}</h3>}
            {unlinked.map(task => (
              <TaskChoice
                key={task.id}
                onClick={() => setSelectedId(task.id)}
                selected={selected?.id === task.id}
                task={task}
              />
            ))}
            {tasks.length === 0 && snapshot && <p>{t('noTasks')}</p>}
          </section>
          <GoalIntake key={`${scope}:${slug}:${projectId}`} onSaved={refresh} projectId={projectId} />
        </aside>
        <div className="workbench-detail">
          {selected && (
            <>
              <section className="workbench-section">
                <h2>{selected.title}</h2>
                <p>
                  {selected.status} · {t('owner')}: {selected.assignee || t('unknown')}
                </p>
                {selected.relationship_state === 'UNKNOWN' && <p>{t('relationUnknown')}</p>}
                <p className="workbench-prose">{missionDescription(selected.body)}</p>
                <h3>{t('next')}</h3>
                <p>{selected.last_failure_error || selected.latest_summary || t('inspect')}</p>
                {related.length > 1 && (
                  <>
                    <h3>{t('workItems')}</h3>
                    {related
                      .filter(task => task.id !== rootId)
                      .map(task => (
                        <TaskChoice
                          key={task.id}
                          onClick={() => setSelectedId(task.id)}
                          selected={selected.id === task.id}
                          task={task}
                        />
                      ))}
                  </>
                )}
              </section>
              {snapshot && <AgentActivity snapshot={snapshot} taskIds={taskIds} />}
              <DeliveryCenter key={`${scope}:${slug}:${selected.id}`} scope={scope} slug={slug} taskId={selected.id} />
            </>
          )}
          {snapshot && (
            <>
              <DecisionInbox decisions={snapshot.decisions} onRecorded={refresh} />
              <SourceUnknowns values={snapshot.unknowns} />
              <small>
                {t('fetched')} {workbenchTime(snapshot.fetched_at)}
              </small>
            </>
          )}
        </div>
      </div>
    </main>
  )
}

export function MissionWorkbench() {
  const scope = useKanbanScope()
  const slug = useValue($boardSlug)

  return <WorkbenchScope key={`${scope}:${slug}`} scope={scope} slug={slug} />
}
