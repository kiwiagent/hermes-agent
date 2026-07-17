import type {
  BillingAutoReload as SharedBillingAutoReload,
  BillingCardInfo,
  BillingChargeResponse,
  BillingChargeStatusResponse,
  BillingErrorPayload,
  BillingMonthlyCap,
  BillingMutationResponse,
  BillingRefusalCode,
  BillingStateResponse as SharedBillingStateResponse,
  ChargeFailureReason,
  SubscriptionStateResponse,
  SubscriptionTierOption,
  UsageBarData,
  UsageModelData
} from '@hermes/shared/billing'

export type {
  BillingCardInfo,
  BillingChargeResponse,
  BillingChargeStatusResponse,
  BillingErrorPayload,
  BillingMonthlyCap,
  BillingMutationResponse,
  BillingRefusalCode,
  ChargeFailureReason,
  SubscriptionStateResponse,
  SubscriptionTierOption,
  UsageBarData,
  UsageModelData
}

export interface BillingDollarBounds {
  maxUsd?: null | string
  max_usd?: null | string
  minUsd?: null | string
  min_usd?: null | string
}

export interface BillingAutoReload extends SharedBillingAutoReload {
  bounds?: BillingDollarBounds | null
}

export type BillingStateResponse = Omit<SharedBillingStateResponse, 'auto_reload'> & {
  auto_reload: BillingAutoReload | null
}

export interface BillingRefusalError {
  kind: string
  message: string
  portal_url?: string | null
  retry_after?: number | null
  payload?: BillingErrorPayload
  actor?: string
  code?: string
  recovery?: string
}

export interface BillingRefusalResponse {
  ok: false
  error: BillingRefusalError
}

export type BillingRpcResponse<T extends { ok?: boolean }> = (Omit<T, 'ok'> & { ok: true }) | BillingRefusalResponse
