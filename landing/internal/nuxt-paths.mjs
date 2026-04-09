const normalizeBaseURL = (value) => {
  if (!value || value === '/') return '/';
  return value.endsWith('/') ? value : `${value}/`;
};

export const baseURL = () => normalizeBaseURL(process.env.NUXT_APP_BASE_URL || '/');
