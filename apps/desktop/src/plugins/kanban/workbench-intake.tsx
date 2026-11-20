import { Button, Input, Textarea, useMutation } from '@hermes/plugin-sdk'
import { useRef, useState } from 'react'

import { confirmMission, previewMission } from './api'
import { useWorkbenchText } from './workbench-i18n'
import type { MissionPlan } from './workbench-types'

export function GoalIntake({ projectId, onSaved }: { projectId: string; onSaved: () => void }) {
  const t = useWorkbenchText()
  const [goal, setGoal] = useState('')
  const [plan, setPlan] = useState<MissionPlan | null>(null)
  const [submitted, setSubmitted] = useState(false)
  const requestId = useRef('')

  const preview = useMutation({
    mutationFn: () => previewMission(goal, projectId),
    onSuccess: result => {
      setPlan(result)
      requestId.current = crypto.randomUUID()
      setSubmitted(false)
    }
  })

  const confirm = useMutation({
    mutationFn: () => {
      if (!plan || plan.status !== 'preview') {
        throw new Error('No plan to confirm')
      }

      setSubmitted(true)

      return confirmMission(plan, projectId, requestId.current)
    },
    onSuccess: onSaved
  })

  const update = (patch: Partial<MissionPlan>) => setPlan(current => current && { ...current, ...patch })

  return (
    <section aria-label={t('goal')} className="workbench-section">
      <h2>{t('goal')}</h2>
      <Textarea
        aria-label={t('goal')}
        disabled={preview.isPending || submitted}
        onChange={event => setGoal(event.target.value)}
        placeholder={t('goalPlaceholder')}
        value={goal}
      />
      <Button
        disabled={!goal.trim() || preview.isPending || submitted}
        onClick={() => {
          setPlan(null)
          preview.mutate()
        }}
        variant="outline"
      >
        {preview.isPending ? t('planning') : t('preview')}
      </Button>
      {preview.isError && <p role="alert">{t('failure')}</p>}
      {plan?.status === 'unavailable' && <p role="status">{t('modelUnavailable')}</p>}
      {plan?.status === 'preview' && (
        <div className="workbench-plan">
          <h3>{t('plan')}</h3>
          <label>
            {t('planTitle')}
            <Input disabled={submitted} onChange={event => update({ title: event.target.value })} value={plan.title} />
          </label>
          <label>
            {t('planBody')}
            <Textarea disabled={submitted} onChange={event => update({ body: event.target.value })} value={plan.body} />
          </label>
          <h3>{t('workItems')}</h3>
          {plan.work_items.map((item, index) => (
            <div className="workbench-plan-item" key={index}>
              <Input
                aria-label={`${t('task')} ${index + 1}`}
                disabled={submitted}
                onChange={event =>
                  update({
                    work_items: plan.work_items.map((value, at) =>
                      at === index ? { ...value, title: event.target.value } : value
                    )
                  })
                }
                value={item.title}
              />
              <Textarea
                aria-label={`${t('planBody')} ${index + 1}`}
                disabled={submitted}
                onChange={event =>
                  update({
                    work_items: plan.work_items.map((value, at) =>
                      at === index ? { ...value, body: event.target.value } : value
                    )
                  })
                }
                value={item.body}
              />
            </div>
          ))}
          {plan.assumptions.length > 0 && (
            <>
              <h3>{t('assumptions')}</h3>
              <ul>
                {plan.assumptions.map((item, index) => (
                  <li key={index}>{item}</li>
                ))}
              </ul>
            </>
          )}
          <small>{plan.model || t('unknown')}</small>
          <p>{t('confirmDetail')}</p>
          <Button
            disabled={
              !plan.title.trim() ||
              plan.work_items.some(item => !item.title.trim()) ||
              confirm.isPending ||
              confirm.isSuccess
            }
            onClick={() => confirm.mutate()}
          >
            {t('confirm')}
          </Button>
          {confirm.isSuccess && (
            <>
              <p role="status">
                {t('saved')} · {confirm.data.root_id}
              </p>
              <Button
                onClick={() => {
                  setGoal('')
                  setPlan(null)
                  setSubmitted(false)
                  requestId.current = ''
                  confirm.reset()
                }}
                variant="ghost"
              >
                {t('another')}
              </Button>
            </>
          )}
          {confirm.isError && <p role="alert">{t('failure')}</p>}
        </div>
      )}
    </section>
  )
}
