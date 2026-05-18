const developmentResponse = {
  'cat /data/adb/treat_wheel/webui_config': {
    errno: 0,
    stdout: `disable_fullscreen=false`,
    stderr: ''
  },
  'cat /data/adb/treat_wheel/state': {
    errno: 0,
    stdout: 'disable_revanced_mounts_umount=true\ndisable_denylist_logic_inversion=true',
    stderr: ''
  },
  'cat /data/adb/treat_wheel/status': {
    errno: 0,
    stdout: 'hiding',
    stderr: ''
  },
  'cat /data/adb/modules/treat_wheel/module.prop': {
    errno: 0,
    stdout: 'id=treat_wheel\nversion=1.2.3\nname=Treat Wheel\nversionCode=123\nauthor=ThePedroo\n',
    stderr: ''
  },
  '/data/adb/ksud debug version': {
    errno: 0,
    stdout: 'Kernel Version: 12345',
    stderr: ''
  },
  '/system/bin/ls /data/adb/modules/rezygisk/webroot/lang': {
    errno: 0,
    stdout: 'ar_EG.json\nde_DE.json\nes_AR.json\nid_ID.json\nja_JP.json\npt_BR.json\ntr_TR.json\nvi_VN.json\nen_US.json\nes_MX.json\nit_IT.json\nko_KR.json\nru_RU.json\nuk_UA.json\nzh_CN.json',
    stderr: ''
  }
}

export function getDevelopmentExecResponse(command) {
  if (developmentResponse[command]) {
    return developmentResponse[command]
  }

  if (command.includes('printf % ; if test -f')) {
    return developmentResponse['module_lister']
  }

  return { errno: -1, stdout: '', stderr: 'Command not found in development response' }
}