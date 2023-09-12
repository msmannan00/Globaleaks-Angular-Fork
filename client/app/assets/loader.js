var elem;

var isBrowserCompatible = function() {
  var crawlers = [
    "Googlebot",
    "Bingbot",
    "Slurp",
    "DuckDuckBot",
    "Baiduspider",
    "YandexBot",
    "Sogou",
    "Exabot",
    "ia_archiver"
  ];

  for (var i = 0; i < crawlers.length; i++) { // Corrected the loop declaration
    if (navigator.userAgent.indexOf(crawlers[i]) !== -1) {
      return true;
    }
  }

  if (typeof window === "undefined") {
    return false;
  }

  if (window.isSecureContext && !window.crypto && !window.crypto.subtle) {
    return false;
  }

  if (!(window.File && window.FileList && window.FileReader)) {
    return false;
  }

  if (typeof Blob === "undefined" ||
    (!Blob.prototype.slice && !Blob.prototype.webkitSlice && !!Blob.prototype.mozSlice)) {
    return false;
  }

  return true;
};

if (!isBrowserCompatible()) {
  document.getElementById("BrowserNotSupported").style.display = "block";
} else {
  elem = document.createElement("link");
  elem.setAttribute("rel", "stylesheet");
  elem.setAttribute("type", "text/css");
  elem.setAttribute("href", "css/styles.css");
  document.getElementsByTagName("head")[0].appendChild(elem);

  // Create and append multiple script elements
  var scriptFiles = ["js/scripts.js", "js/polyfills.js", "js/runtime.js", "js/main.js"];
  for (var i = 0; i < scriptFiles.length; i++) {
    elem = document.createElement("script");
    elem.setAttribute("type", "text/javascript");
    elem.setAttribute("src", scriptFiles[i]);
    document.getElementsByTagName("body")[0].appendChild(elem);
  }
}
