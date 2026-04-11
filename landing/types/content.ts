import type { LocaleCode } from '~/data/i18n';

export interface FeatureItem {
  id: string;
  title: string;
  description: string;
  looksLike: string;
  actuallyDoes: string;
}

export interface FeaturedRuleCard {
  id: string;
  eyebrow: string;
  code: string;
  surface: string;
  lifecycle: string;
  title: string;
  description: string;
  whyItMatters: string;
  evidence: string;
  href: string;
}

export interface FaqItem {
  id: string;
  question: string;
  answer: string;
}

export interface HeroContent {
  title: string;
  subtitle: string;
  supportLine: string;
}

export interface DownloadContent {
  title: string;
  note: string;
}

export interface InstallChannel {
  id: string;
  title: string;
  description: string;
  href: string;
  note: string;
  command?: string;
  recommended?: boolean;
}

export interface QuickstartStep {
  id: string;
  title: string;
  command: string;
  note: string;
}

export interface SupportLane {
  id: string;
  name: string;
  status: string;
  note: string;
}

export interface ComparisonCell {
  status: 'yes' | 'partial' | 'no';
  note: string;
}

export interface ComparisonRow {
  id: string;
  feature: string;
  lintai: ComparisonCell;
  manualReview: ComparisonCell;
  scripts: ComparisonCell;
  cloudScanners: ComparisonCell;
}

export interface LandingContent {
  hero: HeroContent;
  features: FeatureItem[];
  featuredRules: FeaturedRuleCard[];
  comparisonRows: ComparisonRow[];
  faq: FaqItem[];
  download: DownloadContent;
  installChannels: InstallChannel[];
  quickstartSteps: QuickstartStep[];
  supportLanes: SupportLane[];
}

export type LocalizedContent = Record<LocaleCode, LandingContent>;
