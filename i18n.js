(function () {
    var DEFAULT_LANG = 'en';
    var SUPPORTED = ['en', 'vi', 'es', 'pt', 'fr', 'de', 'it', 'ja', 'ko', 'zh', 'th', 'id', 'ms', 'ar', 'hi', 'tr', 'ru', 'pl', 'nl', 'tl', 'cs', 'nb', 'da', 'el', 'fi', 'ro', 'he', 'sv', 'hu'];
    var currentLang = DEFAULT_LANG;

    function applyTranslations(translations) {
        document.querySelectorAll('[data-i18n]').forEach(function (el) {
            var key = el.getAttribute('data-i18n');
            if (translations[key]) {
                if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') {
                    el.setAttribute('placeholder', translations[key]);
                } else {
                    el.innerHTML = translations[key];
                }
            }
        });
        document.querySelectorAll('[data-i18n-placeholder]').forEach(function (el) {
            var key = el.getAttribute('data-i18n-placeholder');
            if (translations[key]) el.setAttribute('placeholder', translations[key]);
        });
    }

    function highlightActiveLang(lang) {
        // Footer language links
        document.querySelectorAll('.footer-lang-link.lang-link').forEach(function (el) {
            var elLang = el.getAttribute('data-lang');
            if (elLang === lang) {
                el.classList.add('footer-lang-active');
            } else {
                el.classList.remove('footer-lang-active');
            }
        });
        // Modal language links
        document.querySelectorAll('.lang-modal-lang').forEach(function (el) {
            var elLang = el.getAttribute('data-lang');
            if (elLang === lang) {
                el.classList.add('current-lang');
            } else {
                el.classList.remove('current-lang');
            }
        });
    }

    function loadLang(lang, callback) {
        if (lang === DEFAULT_LANG) {
            if (!window._i18nOriginals) {
                saveOriginals();
            }
            if (currentLang !== DEFAULT_LANG && window._i18nOriginals) {
                document.querySelectorAll('[data-i18n]').forEach(function (el) {
                    var key = el.getAttribute('data-i18n');
                    if (window._i18nOriginals[key]) el.innerHTML = window._i18nOriginals[key];
                });
                document.querySelectorAll('[data-i18n-placeholder]').forEach(function (el) {
                    var key = el.getAttribute('data-i18n-placeholder');
                    if (window._i18nOriginals[key]) el.setAttribute('placeholder', window._i18nOriginals[key]);
                });
            }
            currentLang = DEFAULT_LANG;
            document.documentElement.lang = 'en';
            document.documentElement.removeAttribute('dir');
            sessionStorage.setItem('i18n_lang', lang);
            highlightActiveLang(lang);
            if (callback) callback();
            return;
        }

        if (!window._i18nOriginals) {
            saveOriginals();
        }

        var basePath = document.querySelector('meta[name="i18n-base"]');
        var base = basePath ? basePath.getAttribute('content') : '.';
        fetch(base + '/lang/' + lang + '.json')
            .then(function (r) { return r.ok ? r.json() : null; })
            .then(function (data) {
                if (data) {
                    applyTranslations(data);
                    currentLang = lang;
                    document.documentElement.lang = lang;
                    if (data._dir) {
                        document.documentElement.dir = data._dir;
                    } else {
                        document.documentElement.removeAttribute('dir');
                    }
                    sessionStorage.setItem('i18n_lang', lang);
                    highlightActiveLang(lang);
                }
                if (callback) callback();
            })
            .catch(function () {
                if (callback) callback();
            });
    }

    function saveOriginals() {
        window._i18nOriginals = {};
        document.querySelectorAll('[data-i18n]').forEach(function (el) {
            window._i18nOriginals[el.getAttribute('data-i18n')] = el.innerHTML;
        });
        document.querySelectorAll('[data-i18n-placeholder]').forEach(function (el) {
            window._i18nOriginals[el.getAttribute('data-i18n-placeholder')] = el.getAttribute('placeholder');
        });
    }

    function detectAndApply() {
        saveOriginals();
        // Scroll to top if language was just switched
        if (sessionStorage.getItem('i18n_scrollTop')) {
            sessionStorage.removeItem('i18n_scrollTop');
            if ('scrollRestoration' in history) history.scrollRestoration = 'manual';
            window.scrollTo(0, 0);
            // Force again after browser's scroll restoration
            setTimeout(function () { window.scrollTo(0, 0); }, 0);
            setTimeout(function () { window.scrollTo(0, 0); }, 50);
            setTimeout(function () { window.scrollTo(0, 0); }, 150);
        }
        // 1. Check sessionStorage cache
        var cached = sessionStorage.getItem('i18n_lang');
        if (cached && SUPPORTED.indexOf(cached) !== -1) {
            loadLang(cached);
            return;
        }
        // 2. Try Vercel API
        fetch('/api/detect-lang')
            .then(function (r) { return r.json(); })
            .then(function (data) {
                var lang = data && data.lang && SUPPORTED.indexOf(data.lang) !== -1 ? data.lang : DEFAULT_LANG;
                loadLang(lang);
            })
            .catch(function () {
                // 3. Fallback: navigator.language
                var navLang = (navigator.language || '').split('-')[0].toLowerCase();
                var lang = SUPPORTED.indexOf(navLang) !== -1 ? navLang : DEFAULT_LANG;
                loadLang(lang);
            });
    }

    // Expose switchLang globally for footer language links
    window.switchLang = function (lang) {
        if (SUPPORTED.indexOf(lang) === -1) lang = DEFAULT_LANG;
        sessionStorage.setItem('i18n_lang', lang);
        sessionStorage.setItem('i18n_scrollTop', '1');
        window.location.reload();
    };

    // "More languages" → open the Select a Language modal
    window.toggleMoreLangs = function () {
        var overlay = document.getElementById('lang-modal-overlay');
        if (overlay) overlay.classList.add('show');
    };

    // Close the language modal
    window.closeLangModal = function () {
        var overlay = document.getElementById('lang-modal-overlay');
        if (overlay) overlay.classList.remove('show');
    };

    // Filter languages by region in the modal
    window.filterLangRegion = function (region) {
        // Highlight active region tab
        document.querySelectorAll('.lang-modal-region').forEach(function (el) {
            if (el.getAttribute('data-region') === region) {
                el.classList.add('active');
            } else {
                el.classList.remove('active');
            }
        });
        // Show/hide language links based on region
        document.querySelectorAll('.lang-modal-lang').forEach(function (el) {
            var regions = (el.getAttribute('data-regions') || '').split(',');
            if (region === 'all' || regions.indexOf(region) !== -1) {
                el.style.display = '';
            } else {
                el.style.display = 'none';
            }
        });
    };

    // Run after DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', detectAndApply);
    } else {
        detectAndApply();
    }
})();
