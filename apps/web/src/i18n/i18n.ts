import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import zh from './locales/zh/common.json';
import en from './locales/en/common.json';

let initialized = false;

export function initI18n(lang: string) {
  if (!initialized) {
    initialized = true;
    i18n.use(initReactI18next).init({
      resources: { zh: { common: zh }, en: { common: en } },
      lng: lang,
      fallbackLng: 'zh',
      defaultNS: 'common',
      interpolation: { escapeValue: false },
    });
  } else if (i18n.language !== lang) {
    i18n.changeLanguage(lang);
  }
}

export default i18n;
