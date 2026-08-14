// ServerAgentLink 前端辅助逻辑。全部操作走 fetch + double-submit CSRF，无外部 CDN 依赖。

function salCookie(name) {
  var m = document.cookie.match(new RegExp('(?:^|; )' + name + '=([^;]*)'));
  return m ? decodeURIComponent(m[1]) : '';
}

function salCsrfHeaders(extra) {
  var h = Object.assign({}, extra || {});
  var t = salCookie('sal_csrf');
  if (t) h['X-CSRF-Token'] = t;
  return h;
}

// 通用 fetch：带 CSRF 头；2xx 解析 JSON 返回，非 2xx 抛出服务端 error 信息。
function salFetch(method, url, body) {
  return fetch(url, {
    method: method,
    headers: salCsrfHeaders(body ? { 'Content-Type': 'application/json' } : {}),
    body: body ? JSON.stringify(body) : undefined,
  }).then(function (r) {
    if (r.status === 204) return null;
    return r.json().catch(function () { return {}; }).then(function (data) {
      if (!r.ok) throw new Error((data && data.error) || ('HTTP ' + r.status));
      return data;
    });
  });
}

function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
  });
}

// 把「/path=mode,/path=mode」解析为权限数组。
function parsePerms(str) {
  return (str || '').split(',').map(function (s) { return s.trim(); }).filter(Boolean).map(function (s) {
    var kv = s.split('=');
    return { path: kv[0].trim(), mode: (kv[1] || 'rw').trim() };
  });
}

// 通用 JSON 表单提交。onOk 缺省为刷新页面。
window.salSubmit = function (formId, url, toBody, onOk, method) {
  var form = document.getElementById(formId);
  if (!form) return;
  form.addEventListener('submit', function (e) {
    e.preventDefault();
    var fd = new FormData(form);
    salFetch(method || 'POST', url, toBody(fd))
      .then(function () { if (onOk) onOk(); else location.reload(); })
      .catch(function (err) { alert('操作失败：' + err.message); });
  });
};

// 连通性测试：调用 /api/servers/{id}/test，把结果写进 data-target 指向的元素。
function salTest(btn) {
  var id = btn.getAttribute('data-id');
  var target = document.getElementById(btn.getAttribute('data-target'));
  var original = btn.textContent;
  btn.disabled = true;
  btn.textContent = '测试中…';
  salFetch('POST', '/api/servers/' + id + '/test', {})
    .then(function (res) {
      if (target) {
        if (res.connected) {
          target.innerHTML = '<span class="dot dot-ok"></span>已连通' +
            (res.host_key ? ' · <span class="mono fp">' + esc(res.host_key) + '</span>' : '');
        } else {
          target.innerHTML = '<span class="dot dot-bad"></span>连接失败 · <span class="mono err">' + esc(res.error) + '</span>';
        }
      }
    })
    .catch(function (err) {
      if (target) target.innerHTML = '<span class="dot dot-bad"></span>连接失败 · <span class="mono err">' + esc(err.message) + '</span>';
    })
    .finally(function () { btn.disabled = false; btn.textContent = original; });
}

// 退出登录。
(function () {
  var lo = document.getElementById('logout');
  if (lo) lo.addEventListener('submit', function (e) {
    e.preventDefault();
    salFetch('POST', '/api/logout', {}).then(function () { location.href = '/login'; });
  });
})();

// data-action 按钮：删服务器/删账户/重新建户（测试连通单独处理）。
document.addEventListener('click', function (ev) {
  var btn = ev.target.closest('[data-action]');
  if (!btn) return;
  var action = btn.getAttribute('data-action');
  if (action === 'test-server') { salTest(btn); return; }

  var id = btn.getAttribute('data-id');
  if (action === 'toggle-flag') {
    var flag = btn.getAttribute('data-flag');
    var body = {};
    body[flag] = !btn.classList.contains('on');
    salFetch('PUT', '/api/accounts/' + id, body)
      .then(function () { location.reload(); })
      .catch(function (err) { alert('操作失败：' + err.message); });
    return;
  }

  var url = '', method = 'POST';
  if (action === 'delete-server') { url = '/api/servers/' + id; method = 'DELETE'; }
  else if (action === 'delete-account') { url = '/api/accounts/' + id; method = 'DELETE'; }
  else if (action === 'provision') { url = '/api/accounts/' + id + '/provision'; }

  var msg = btn.getAttribute('data-confirm');
  if (msg && !window.confirm(msg)) return;
  salFetch(method, url).then(function () { location.reload(); })
    .catch(function (err) { alert('操作失败：' + err.message); });
});

// 行内「改权限」与「改密码」表单。
document.addEventListener('submit', function (ev) {
  var f = ev.target;
  if (f.classList.contains('perm-form')) {
    ev.preventDefault();
    var msg = f.querySelector('.msg');
    salFetch('PUT', '/api/accounts/' + f.getAttribute('data-account') + '/permissions',
      parsePerms(f.elements['perms'].value))
      .then(function () { location.reload(); })
      .catch(function (err) { msg.textContent = '失败：' + err.message; msg.classList.add('err'); });
  } else if (f.classList.contains('pwd-form')) {
    ev.preventDefault();
    var m2 = f.querySelector('.msg');
    var pw = f.elements['password'].value;
    if (!pw) { m2.textContent = '请输入新密码'; m2.classList.add('err'); return; }
    salFetch('PUT', '/api/accounts/' + f.getAttribute('data-account') + '/password', { password: pw })
      .then(function () { m2.textContent = '已更新'; m2.classList.remove('err'); f.elements['password'].value = ''; })
      .catch(function (err) { m2.textContent = '失败：' + err.message; m2.classList.add('err'); });
  }
});
