/* INFO: Wait until the CSS animation ends, with a timeout fallback to avoid hanging transitions. */
function waitForAnimationEnd(element, fallbackMs = 280) {
  return new Promise((resolve) => {
    let done = false

    const finalize = () => {
      if (done) return
      done = true
      element.removeEventListener('animationend', finalize)
      element.removeEventListener('animationcancel', finalize)
      resolve()
    }

    element.addEventListener('animationend', finalize, { once: true })
    element.addEventListener('animationcancel', finalize, { once: true })
    setTimeout(finalize, fallbackMs)
  })
}

export async function runMainPageTransition(currentPageContent, nextPageContent, direction = 1) {
  /* INFO: MD3 shared-axis style navigation keeps pages side-by-side and pushes them together. */
  const viewport = currentPageContent.parentElement
  const incomingFrom = direction > 0 ? '30px' : '-30px'
  const outgoingTo = direction > 0 ? '-30px' : '30px'

  viewport.classList.add('page_loader_main_viewport_transition')

  nextPageContent.style.display = 'block'
  currentPageContent.style.setProperty('--page_loader_main_out_to', outgoingTo)
  nextPageContent.style.setProperty('--page_loader_main_in_from', incomingFrom)

  currentPageContent.style.pointerEvents = 'none'
  nextPageContent.style.pointerEvents = 'none'
  currentPageContent.classList.add('page_loader_main_transition', 'page_loader_main_out')
  nextPageContent.classList.add('page_loader_main_transition', 'page_loader_main_in')

  /* INFO: Force style application before animation starts */
  nextPageContent.getBoundingClientRect()

  await Promise.all([
    waitForAnimationEnd(currentPageContent, 380),
    waitForAnimationEnd(nextPageContent, 380),
  ])

  currentPageContent.classList.remove('page_loader_main_transition', 'page_loader_main_out')
  nextPageContent.classList.remove('page_loader_main_transition', 'page_loader_main_in')
  currentPageContent.style.removeProperty('--page_loader_main_out_to')
  nextPageContent.style.removeProperty('--page_loader_main_in_from')
  currentPageContent.style.removeProperty('pointer-events')
  nextPageContent.style.removeProperty('pointer-events')
  viewport.classList.remove('page_loader_main_viewport_transition')

  currentPageContent.style.display = 'none'
  nextPageContent.style.display = 'block'
}

export async function runMiniPageEnter(pageSpecificContent) {
  /* INFO: Mini pages slide in as an overlay from the right side. */
  pageSpecificContent.classList.add('page_loader_mini_in')
  pageSpecificContent.style.display = 'block'

  await waitForAnimationEnd(pageSpecificContent)

  pageSpecificContent.classList.remove('page_loader_mini_in')
}

export async function runMiniPageLeave(pageSpecificContent) {
  /* INFO: Mini pages slide out to the right and then become hidden. */
  pageSpecificContent.classList.add('page_loader_mini_out')

  await waitForAnimationEnd(pageSpecificContent)

  pageSpecificContent.classList.remove('page_loader_mini_out')
  pageSpecificContent.style.display = 'none'
}
