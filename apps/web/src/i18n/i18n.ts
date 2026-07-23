import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import zh from './locales/zh/common.json';
import en from './locales/en/common.json';

const savedLang = typeof window !== 'undefined'
  ? localStorage.getItem('tah-lang') || 'zh'
  : 'zh';

i18n.use(initReactI18next).init({
  resources: {
    zh: { common: zh },
    en: { common: en },
  },
  lng: savedLang,
  fallbackLng: 'zh',
  defaultNS: 'common',
  interpolation: {
    escapeValue: false,
  },
});

export default i18n;
