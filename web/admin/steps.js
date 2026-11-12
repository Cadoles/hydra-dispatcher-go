// The rows of the steps of a flow, dragged to order them: the positions
// follow the order of the rows. Without this script, they are typed.
(() => {
  "use strict";
  const body = document.querySelector("#steps tbody");
  if (!body) {
    return;
  }
  let dragged = null;
  const renumber = () => {
    let n = 0;
    for (const row of body.rows) {
      const app = row.querySelector("select[name=step_app]");
      const position = row.querySelector("input[name=step_position]");
      if (app && position && app.value !== "") {
        position.value = String(++n);
      }
    }
  };
  for (const row of body.rows) {
    row.draggable = true;
    row.addEventListener("dragstart", (e) => {
      dragged = row;
      if (e.dataTransfer) {
        e.dataTransfer.effectAllowed = "move";
        e.dataTransfer.setData("text/plain", "");
      }
    });
    row.addEventListener("dragover", (e) => {
      if (!dragged || dragged === row) {
        return;
      }
      e.preventDefault();
      const box = row.getBoundingClientRect();
      body.insertBefore(dragged, e.clientY < box.top + box.height / 2 ? row : row.nextSibling);
    });
    row.addEventListener("drop", (e) => e.preventDefault());
    row.addEventListener("dragend", () => {
      dragged = null;
      renumber();
    });
  }
})();
