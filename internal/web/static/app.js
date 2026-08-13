// ServerAgentLink 前端辅助逻辑。

function salCookie(name) {
  const m = document.cookie.match(new RegExp('(?:^|; )' + name + '=([^;]*)'));
  return m ? decodeURIComponent(m[1]) : '';
}

function salCsrfHeaders(extra) {
  const h = Object.assign({}, extra || {});
  const t = salCookie('sal_csrf');
  if (t) h['X-CSRF-Token'] = t;
  return h;
}

// htmx 发起的请求（删除/建户等）自动附带 CSRF 头。
document.addEventListener('htmx:configRequest', function (ev) {
  const t = salCookie('sal_csrf');
  if (t) ev.detail.headers['X-CSRF-Token'] = t;
});

// 通用 JSON 表单提交：从表单收集字段构造 body，POST 后刷新页面或回调。
window.salSubmit = function (formId, url, toBody, onOk) {
  var form = document.getElementById(formId);
  if (!form) return;
  form.addEventListener('submit', function (e) {
    e.preventDefault();
    var fd = new FormData(form);
    fetch(url, {
      method: 'POST',
      headers: salCsrfHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify(toBody(fd)),
    })
      .then(function (r) {
        if (r.ok) { if (onOk) onOk(); else location.reload(); }
        else return r.text().then(function (t) { throw new Error(t); });
      })
      .catch(function (err) { alert('操作失败：' + err.message); });
  });
};
