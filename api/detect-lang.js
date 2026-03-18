const COUNTRY_TO_LANG = {
    US: 'en', GB: 'en', AU: 'en', CA: 'en', NZ: 'en', IE: 'en', ZA: 'en', JM: 'en', TT: 'en', GH: 'en', NG: 'en', KE: 'en',
    VN: 'vi',
    ES: 'es', MX: 'es', AR: 'es', CO: 'es', CL: 'es', PE: 'es', VE: 'es', EC: 'es', GT: 'es', CU: 'es', BO: 'es', DO: 'es', HN: 'es', PY: 'es', SV: 'es', NI: 'es', CR: 'es', PA: 'es', UY: 'es', PR: 'es',
    BR: 'pt', PT: 'pt', AO: 'pt', MZ: 'pt',
    FR: 'fr', BE: 'fr', SN: 'fr', CI: 'fr', CM: 'fr', MG: 'fr', ML: 'fr', BF: 'fr', NE: 'fr', TD: 'fr', GN: 'fr', RW: 'fr', HT: 'fr', LU: 'fr', MC: 'fr',
    DE: 'de', AT: 'de', LI: 'de',
    CH: 'de',
    IT: 'it', SM: 'it', VA: 'it',
    JP: 'ja',
    KR: 'ko',
    CN: 'zh', TW: 'zh', HK: 'zh', MO: 'zh', SG: 'zh',
    TH: 'th',
    ID: 'id',
    MY: 'ms', BN: 'ms',
    SA: 'ar', AE: 'ar', EG: 'ar', IQ: 'ar', MA: 'ar', DZ: 'ar', SD: 'ar', SY: 'ar', YE: 'ar', TN: 'ar', JO: 'ar', LY: 'ar', LB: 'ar', OM: 'ar', KW: 'ar', QA: 'ar', BH: 'ar', PS: 'ar',
    IN: 'hi',
    TR: 'tr', CY: 'tr',
    RU: 'ru', BY: 'ru', KZ: 'ru', KG: 'ru', TJ: 'ru',
    PL: 'pl',
    NL: 'nl', SR: 'nl',
    PH: 'tl',
    CZ: 'cs', SK: 'cs',
    NO: 'nb',
    DK: 'da',
    GR: 'el',
    FI: 'fi',
    RO: 'ro', MD: 'ro',
    IL: 'he',
    SE: 'sv',
    HU: 'hu',
};

const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '';

module.exports = (req, res) => {
    const country = req.headers['x-vercel-ip-country'] || 'US';
    const lang = COUNTRY_TO_LANG[country] || 'en';

    const origin = req.headers.origin || '';
    let corsOrigin = '';

    if (ALLOWED_ORIGIN && origin === ALLOWED_ORIGIN) {
        corsOrigin = origin;
    } else if (!ALLOWED_ORIGIN && (!origin || origin.endsWith('.vercel.app'))) {
        corsOrigin = origin || '*';
    }

    if (corsOrigin) {
        res.setHeader('Access-Control-Allow-Origin', corsOrigin);
    }
    res.setHeader('Vary', 'Origin');
    res.setHeader('Cache-Control', 'public, max-age=3600');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.json({ country, lang });
};
