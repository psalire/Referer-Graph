
window.onload = () => {
    // https://spin.atomicobject.com/2019/11/21/creating-a-resizable-html-element/
    const getResizeableElement = () => { return document.getElementById("sidebar"); };
    const getHandleElement = () => { return document.getElementById("handle"); };
    const minPaneSize = 100;
    getResizeableElement().style.setProperty('--min-width', `${minPaneSize}px`);

    const setPaneWidth = (width) => {
      getResizeableElement().style
        .setProperty('--resizeable-width', `${width}px`);
    };

    const getPaneWidth = () => {
      const pxWidth = getComputedStyle(getResizeableElement())
        .getPropertyValue('--resizeable-width');
      return parseInt(pxWidth, 10);
    };

    const startDragging = (event) => {
      event.preventDefault();
      const startingPaneWidth = getPaneWidth();
      const xOffset = event.pageX;

      const mouseDragHandler = (moveEvent) => {
        moveEvent.preventDefault();
        const primaryButtonPressed = moveEvent.buttons === 1;
        if (!primaryButtonPressed) {
          setPaneWidth(Math.max(getPaneWidth(), minPaneSize));
          document.body.removeEventListener('pointermove', mouseDragHandler);
          return;
        }

        const paneOriginAdjustment = 'left' === 'right' ? 1 : -1;
        setPaneWidth((xOffset - moveEvent.pageX ) * paneOriginAdjustment + startingPaneWidth);
      };
      document.body.addEventListener('pointermove', mouseDragHandler);
    };

    getHandleElement().addEventListener('mousedown', startDragging);
}
