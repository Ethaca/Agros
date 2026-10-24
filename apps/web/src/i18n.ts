/** PR 리포트 언어. 사용자 설정(users.report_lang)이 없으면 REPORT_LANG, 그것도 없으면 영어 */
export type Lang = 'en' | 'ko';
export const LANGS: Lang[] = ['en', 'ko'];
export const DEFAULT_LANG: Lang = 'en';
export const isLang = (v: unknown): v is Lang => v === 'en' || v === 'ko';
export const LANG_NAMES: Record<Lang, string> = { en: 'English', ko: '한국어' };

/** 같은 문구의 언어별 값 */
export type Text = Record<Lang, string>;
export const t = (text: Text, lang: Lang): string => text[lang];
