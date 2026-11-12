import { exec, toast, fullScreen } from './kernelsu.js'

const initialLang = localStorage.getItem('/TreatWheel/language') || 'en_US'
document.documentElement.dir = initialLang === 'ar_EG' ? 'rtl' : 'ltr'

const WebUIConfig = JSON.parse(localStorage.getItem('/TreatWheel/webui_config') || '{}')
if (!WebUIConfig.disableFullscreen) fullScreen(true)
