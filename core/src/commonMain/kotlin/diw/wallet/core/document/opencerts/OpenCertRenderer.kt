package diw.wallet.core.document.opencerts

import kotlinx.serialization.json.JsonPrimitive

/**
 * The host page of an OpenAttestation decentralized renderer: the issuer's template site runs in an iframe and talks
 * to its parent over penpal (version 5: syn, synAck, ack; version 4: handshake, handshake-reply), the protocol of
 * decentralized-renderer-react-components. The host renders the document with RENDER_DOCUMENT (or the older
 * renderDocument call), follows UPDATE_HEIGHT and UPDATE_TEMPLATES, and selects a template with SELECT_TEMPLATE (or
 * selectTemplateTab). The handshake is written here so nothing is loaded besides the issuer's own renderer.
 */
object OpenCertRenderer {
    /** The origin the host page is loaded under (a WebView base URL); it never resolves. */
    const val HOST_BASE_URL = "https://opencerts-host.diw-wallet.invalid/"

    /** The renderer's https origin, or null when the template is missing or not https. */
    fun rendererOrigin(doc: OpenAttestationDocument): String? {
        val url = doc.templateUrl ?: return null
        val m = Regex("^(https://[A-Za-z0-9.-]+(?::\\d+)?)(/.*)?$").matchEntire(url.trim()) ?: return null
        return m.groupValues[1]
    }

    /** The host page for [doc], or null when its template is not an https renderer. */
    fun hostPage(doc: OpenAttestationDocument): String? {
        val origin = rendererOrigin(doc) ?: return null
        val src = doc.templateUrl!!.trim()
        val values = mapOf(
            "SRC" to attr(src),
            "ORIGIN_JS" to script(OpenAttestationDocument.stringify(JsonPrimitive(origin))),
            "DOCUMENT" to script(OpenAttestationDocument.stringify(doc.rendererDocument())),
            "RAW" to script(OpenAttestationDocument.stringify(doc.raw)),
        )
        // One pass, so that a value containing a placeholder is not replaced again.
        return Regex("%(SRC|ORIGIN_JS|DOCUMENT|RAW)%").replace(PAGE) { values.getValue(it.groupValues[1]) }
    }

    /** JSON for a script element: "<" can only appear inside strings, where its escape means the same. */
    private fun script(json: String): String = json.replace("<", "\\u003c").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")

    private fun attr(s: String): String = s.replace("&", "&amp;").replace("\"", "&quot;").replace("<", "&lt;").replace(">", "&gt;")

    private val PAGE = """
<!doctype html>
<html lang="zh-Hant">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body { margin: 0; font-family: sans-serif; background: #fff; color: #1b1b1f; }
  #tabs { display: flex; flex-wrap: wrap; gap: 6px; padding: 8px; }
  #tabs button { border: 1px solid #c5c6d0; background: #fff; border-radius: 16px; padding: 6px 12px; font-size: 14px; }
  #tabs button.on { background: #3f51b5; border-color: #3f51b5; color: #fff; }
  #status { padding: 12px; font-size: 14px; color: #5d5e66; }
  iframe { width: 100%; border: 0; height: 600px; display: block; }
</style>
</head>
<body>
<div id="tabs"></div>
<div id="status">正在載入發證機構的顯示樣式</div>
<iframe id="frame" src="%SRC%" sandbox="allow-scripts allow-same-origin allow-modals allow-popups"></iframe>
<script>
(function () {
  var ORIGIN = %ORIGIN_JS%;
  var DOC = %DOCUMENT%;
  var RAW = %RAW%;
  var frame = document.getElementById('frame');
  var tabs = document.getElementById('tabs');
  var status = document.getElementById('status');
  var methods = [];
  var nextId = 1;
  var pending = {};
  var connected = false;

  function post(message) { frame.contentWindow.postMessage(message, ORIGIN); }

  function call(name, args) {
    var id = 'h' + (nextId++);
    return new Promise(function (resolve, reject) {
      pending[id] = { resolve: resolve, reject: reject };
      post({ penpal: 'call', id: id, methodName: name, args: args });
    });
  }

  // The reported height leaves out the body margins of some renderers.
  function setHeight(h) { if (typeof h === 'number' && h > 0) frame.style.height = (Math.ceil(h) + 48) + 'px'; }

  function setTemplates(list) {
    tabs.innerHTML = '';
    if (!list || list.length < 2) return;
    list.forEach(function (t, i) {
      var b = document.createElement('button');
      b.textContent = t.label || t.id || String(i + 1);
      if (i === 0) b.className = 'on';
      b.onclick = function () {
        Array.prototype.forEach.call(tabs.children, function (c) { c.className = ''; });
        b.className = 'on';
        if (methods.indexOf('dispatch') >= 0) call('dispatch', [{ type: 'SELECT_TEMPLATE', payload: t.id }]);
        else if (methods.indexOf('selectTemplateTab') >= 0) call('selectTemplateTab', [i]);
      };
      tabs.appendChild(b);
    });
  }

  // Calls from the renderer.
  var host = {
    dispatch: function (action) {
      if (!action) return;
      if (action.type === 'UPDATE_HEIGHT') setHeight(action.payload);
      else if (action.type === 'UPDATE_TEMPLATES') setTemplates(action.payload);
      else if (action.type === 'TIMEOUT') status.textContent = '發證機構的顯示樣式沒有回應';
    },
    updateHeight: function (h) { setHeight(h); },
    updateTemplates: function (list) { setTemplates(list); }
  };

  function render() {
    connected = true;
    status.style.display = 'none';
    if (methods.indexOf('dispatch') >= 0) call('dispatch', [{ type: 'RENDER_DOCUMENT', payload: { document: DOC, rawDocument: RAW } }]);
    else if (methods.indexOf('renderDocument') >= 0) call('renderDocument', [DOC, RAW]);
    else status.textContent = '發證機構的顯示樣式不支援這個版本';
  }

  window.addEventListener('message', function (event) {
    if (event.source !== frame.contentWindow || event.origin !== ORIGIN || !event.data) return;
    var m = event.data;
    if (m.penpal === 'syn') {
      post({ penpal: 'synAck', methodNames: Object.keys(host) });
    } else if (m.penpal === 'ack' || m.penpal === 'handshake') {
      if (m.penpal === 'handshake') post({ penpal: 'handshake-reply', methodNames: Object.keys(host) });
      methods = m.methodNames || [];
      render();
    } else if (m.penpal === 'call') {
      var fn = host[m.methodName];
      var value;
      try { value = fn ? fn.apply(host, m.args || []) : undefined; } catch (e) { value = undefined; }
      post({ penpal: 'reply', id: m.id, resolution: 'fulfilled', returnValue: value === undefined ? null : value });
    } else if (m.penpal === 'reply' && pending[m.id]) {
      var p = pending[m.id];
      delete pending[m.id];
      (m.resolution === 'fulfilled' ? p.resolve : p.reject)(m.returnValue);
    }
  });

  setTimeout(function () { if (!connected) status.textContent = '無法連線到發證機構的顯示樣式（' + ORIGIN + '）'; }, 20000);
})();
</script>
</body>
</html>
""".trimStart()
}
