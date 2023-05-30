export class rtipsResolverModel {
  questionnaires: Questionnaires
  rtips: Rtip[]
}

export interface Questionnaires {
  id: string
  questionnaire_id: string
  order: number
  triggered_by_score: number
  triggered_by_options: any[]
  children: Children[]
  label: string
  description: string
}

export interface Children {
  id: string
  instance: string
  editable: boolean
  type: string
  template_id: string
  template_override_id: string
  step_id: string
  fieldgroup_id: string
  multi_entry: boolean
  required: boolean
  preview: boolean
  attrs: Attrs
  x: number
  y: number
  width: number
  triggered_by_score: number
  triggered_by_options: TriggeredByOption[]
  options: Option[]
  children: any[]
  label: string
  description: string
  hint: string
  placeholder: string
}

export interface Attrs {
  input_validation?: InputValidation
  max_len?: MaxLen
  min_len?: MinLen
  regexp?: Regexp
  display_alphabetically?: DisplayAlphabetically
}

export interface InputValidation {
  name: string
  type: string
  value: string
}

export interface MaxLen {
  name: string
  type: string
  value: string
}

export interface MinLen {
  name: string
  type: string
  value: string
}

export interface Regexp {
  name: string
  type: string
  value: string
}

export interface DisplayAlphabetically {
  name: string
  type: string
  value: boolean
}

export interface TriggeredByOption {
  field: string
  option: string
  sufficient: boolean
}

export interface Option {
  id: string
  order: number
  block_submission: boolean
  score_points: number
  score_type: string
  trigger_receiver: any[]
  hint1: string
  hint2: string
  label: string
}

export interface Rtip {
  id: string
  itip_id: string
  creation_date: string
  access_date: string
  last_access: string
  update_date: string
  expiration_date: string
  reminder_date: string
  progressive: number
  important: boolean
  label: string
  updated: boolean
  context_id: string
  tor: boolean
  questionnaire: string
  answers: Answers
  score: number
  status: string
  substatus: any
  file_count: number
  comment_count: number
  message_count: number
}

export interface Answers {
  required_status: boolean
  value: string
}
