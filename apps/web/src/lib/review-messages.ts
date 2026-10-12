import type { TFunction } from 'i18next';
import type { ReviewAdvisory } from '@/types';

/** Localize scanner-authored templates while preserving arbitrary evidence text. */
export function advisoryMessages(advisory: ReviewAdvisory, t: TFunction) {
  if (advisory.code !== 'artifact_verifiers_unavailable') return advisory;
  const capabilities = Array.from(new Set(advisory.description.match(/\b(signature|attestation|sbom)\b/g) ?? []));
  return {
    ...advisory,
    title: t('review.detail.verifiers_unavailable_title'),
    description: capabilities.length ? t('review.detail.verifiers_unavailable_description', {
      capabilities: capabilities.map(capability => t(`review.detail.provenance_verification_${capability}`)).join(', '),
    }) : advisory.description,
    evidence: advisory.evidence === 'verifier capability is unavailable'
      ? t('review.detail.verifier_unavailable') : advisory.evidence,
  };
}
