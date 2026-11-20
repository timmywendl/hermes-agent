import { Button, Textarea, useMutation, useQuery } from '@hermes/plugin-sdk'
import { useState } from 'react'

import { fetchDelivery, respondToDecision } from './api'
import { useWorkbenchText } from './workbench-i18n'
import type { WorkbenchDecision, WorkbenchSnapshot } from './workbench-types'
import { workbenchTime } from './workbench-view'

export function SourceUnknowns({ values }: { values: string[] }) {
  const t = useWorkbenchText()

  return values.length > 0 ? (
    <details className="workbench-unknowns">
      <summary>
        {t('sourceUnknowns')} · {values.length}
      </summary>
      <ul>
        {values.map((value, index) => (
          <li key={index}>{value}</li>
        ))}
      </ul>
    </details>
  ) : null
}

export function AgentActivity({ snapshot, taskIds }: { snapshot: WorkbenchSnapshot; taskIds: Set<string> }) {
  const t = useWorkbenchText()
  const runs = snapshot.runs.filter(run => taskIds.has(run.task_id))
  const events = snapshot.activity.filter(event => taskIds.has(event.task_id))

  return (
    <section aria-label={t('activity')} className="workbench-section">
      <h2>{t('activity')}</h2>
      {runs.length === 0 && <p className="workbench-muted">{t('noRuns')}</p>}
      {runs.map(run => (
        <article className="workbench-run" key={run.id}>
          <header>
            <strong>
              {t('run')} {run.id}
            </strong>
            <span>
              {run.profile || t('unknown')} · {run.status}
            </span>
            <span>{run.outcome || t('unknown')}</span>
          </header>
          <p>
            {t('custody')}: {run.custody_state || t('unknown')}
          </p>
          {run.error && <p role="status">{run.error}</p>}
          {run.summary && (
            <>
              <small>{t('evidence')}</small>
              <p className="workbench-prose">{run.summary}</p>
            </>
          )}
        </article>
      ))}
      <h3>{t('history')}</h3>
      {events.length === 0 && <p className="workbench-muted">{t('noHistory')}</p>}
      <ol className="workbench-timeline">
        {events.map(event => (
          <li key={event.id}>
            <time>{new Date(event.created_at * 1000).toLocaleString()}</time>
            <span>{event.kind}</span>
            {event.payload != null && (
              <details>
                <summary>{t('evidence')}</summary>
                <pre>{typeof event.payload === 'string' ? event.payload : JSON.stringify(event.payload, null, 2)}</pre>
              </details>
            )}
          </li>
        ))}
      </ol>
    </section>
  )
}

export function DeliveryCenter({ scope, slug, taskId }: { scope: string; slug: string; taskId: string }) {
  const t = useWorkbenchText()

  const query = useQuery({
    queryKey: ['kanban', 'workbench-delivery', scope, slug, taskId],
    queryFn: () => fetchDelivery(taskId),
    retry: false,
    staleTime: 30_000
  })

  const delivery = query.data

  return (
    <section aria-label={t('delivery')} className="workbench-section">
      <header className="workbench-section-heading">
        <h2>{t('delivery')}</h2>
        <Button disabled={query.isFetching} onClick={() => void query.refetch()} size="sm" variant="ghost">
          {t('refresh')}
        </Button>
      </header>
      {query.isPending && <p role="status">{t('unknown')}</p>}
      {query.isError && <p role="alert">{delivery ? t('stale') : t('noDelivery')}</p>}
      {delivery && (
        <>
          <p>
            {delivery.url && /^https:\/\/github\.com\/[^/]+\/[^/]+\/pull\/\d+$/.test(delivery.url) ? (
              <a href={delivery.url} rel="noreferrer" target="_blank">
                {delivery.repo} #{delivery.number}
              </a>
            ) : (
              t('noDelivery')
            )}
            {delivery.draft && <span> · {t('draft')}</span>}
          </p>
          <code>{delivery.head || t('unknown')}</code>
          <dl className="workbench-facts">
            <dt>{t('review')}</dt>
            <dd>{delivery.review.state}</dd>
            <dt>{t('ci')}</dt>
            <dd>{delivery.ci.state}</dd>
          </dl>
          {delivery.waiting_for_human_merge && <p role="status">{t('merge')}</p>}
          <ul>
            {delivery.ci.checks.map((check, index) => (
              <li key={index}>
                {check.name} · {check.conclusion || check.status || check.state || t('unknown')}
              </li>
            ))}
          </ul>
          {delivery.review.entries.map((review, index) => (
            <p key={index}>
              {review.author || t('unknown')} · {review.state} · {review.head_sha || review.head || t('unknown')}
            </p>
          ))}
          <h3>
            {t('files')} · {delivery.files.length}
          </h3>
          <ul>
            {delivery.files.map(file => (
              <li key={file.path}>
                <code>{file.path}</code> +{file.additions} −{file.deletions}
              </li>
            ))}
          </ul>
          <SourceUnknowns values={delivery.unknowns} />
          <small>
            {t('fetched')} {workbenchTime(delivery.fetched_at)}
          </small>
        </>
      )}
    </section>
  )
}

function Decision({ decision, onRecorded }: { decision: WorkbenchDecision; onRecorded: () => void }) {
  const t = useWorkbenchText()
  const [response, setResponse] = useState('')

  const mutation = useMutation({
    mutationFn: () => respondToDecision(decision.task_id, decision.id, response),
    onSuccess: onRecorded
  })

  const pending = decision.status === 'pending'

  return (
    <article className="workbench-decision">
      <h3>
        {decision.title} · {decision.status}
      </h3>
      <dl>
        <dt>{t('reason')}</dt>
        <dd>{decision.reason || t('unknown')}</dd>
        <dt>{t('recommendation')}</dt>
        <dd>{decision.recommendation || t('unknown')}</dd>
      </dl>
      {decision.history.map((item, index) => (
        <p key={index}>{item.body}</p>
      ))}
      {pending && (
        <>
          <Textarea aria-label={t('response')} onChange={event => setResponse(event.target.value)} value={response} />
          <p className="workbench-muted">{t('recordDetail')}</p>
          <Button
            disabled={!response.trim() || mutation.isPending || mutation.isSuccess}
            onClick={() => mutation.mutate()}
            variant="outline"
          >
            {t('record')}
          </Button>
        </>
      )}
      {mutation.isSuccess && <p role="status">{t('recorded')}</p>}
      {mutation.isError && <p role="alert">{t('requestFailed')}</p>}
    </article>
  )
}

export function DecisionInbox({ decisions, onRecorded }: { decisions: WorkbenchDecision[]; onRecorded: () => void }) {
  const t = useWorkbenchText()

  return (
    <section aria-label={t('decisions')} className="workbench-section">
      <h2>
        {t('decisions')} · {decisions.filter(item => item.status === 'pending').length}
      </h2>
      {decisions.length === 0 && <p className="workbench-muted">{t('noDecisions')}</p>}
      {decisions.map(decision => (
        <Decision decision={decision} key={decision.id} onRecorded={onRecorded} />
      ))}
    </section>
  )
}
