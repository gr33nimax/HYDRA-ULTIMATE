"""Страница протокола «VLESS через CDN»: регион сервера, погода, часы и подвал.

Страница описывает **сервер**, а не посетителя, и собирается целиком на сервере, кроме
часов: их рисует встроенный скрипт по идентификаторам IANA-зон, поэтому время не
«замерзает» между обновлениями и не требует внешнего API. Внешних хостов на странице
нет вообще — стили и скрипт внутри, изображение отдаётся локально.
"""

from __future__ import annotations

import html
from dataclasses import dataclass, field

from hydra.contracts.vless_cdn import MEDIA_PLAYLIST_PATH
from hydra.core.weather import WeatherView

DEFAULT_TITLE = "Regional Network Status"


@dataclass(frozen=True)
class ImageView:
    """Местное изображение региона и его атрибуция."""

    src: str = ""
    attribution: str = ""
    source: str = ""


@dataclass(frozen=True)
class SiteData:
    """Всё, что нужно странице; ничего из этого не зависит от посетителя."""

    country: str = ""
    country_code: str = ""
    flag: str = ""
    city: str = ""
    capital: str = ""
    timezone: str = ""
    extra_zones: tuple[tuple[str, str], ...] = ()
    updated: str = ""
    status: str = ""
    weather: WeatherView = field(default_factory=WeatherView)
    image: ImageView = field(default_factory=ImageView)

    @property
    def place(self) -> str:
        return self.city or self.country or "Unknown location"

    @property
    def zones(self) -> tuple[tuple[str, str], ...]:
        """Основная зона первой, дополнительные — следом, без повторов."""
        zones: list[tuple[str, str]] = []
        seen: set[str] = set()
        for label, zone in ((self.city, self.timezone), *self.extra_zones):
            if zone and zone not in seen:
                seen.add(zone)
                zones.append((label or zone, zone))
        return tuple(zones)


def _escape(value: object) -> str:
    return html.escape(str(value or ""), quote=True)


def _styles() -> str:
    return """
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body {
  margin: 0; padding: 2.5rem 1.25rem; min-height: 100vh;
  font: 16px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  background: #0e1116; color: #e6edf3;
}
main { max-width: 720px; margin: 0 auto; }
header { display: flex; align-items: baseline; gap: .6rem; flex-wrap: wrap; }
h1 { font-size: 1.6rem; margin: 0; font-weight: 600; }
.sub { color: #8b949e; }
.flag { font-size: 1.6rem; }
.hero { margin: 1.5rem 0 0; padding: 0; }
.hero img { width: 100%; height: auto; border-radius: 12px; display: block; }
.hero.placeholder {
  height: 180px; border-radius: 12px;
  background: linear-gradient(135deg, #1b2430, #243347 60%, #1b2430);
}
.live { margin: 1.5rem 0 0; }
.live-video { width: 100%; aspect-ratio: 16 / 9; display: block; border-radius: 12px;
  background: #0b0e13; object-fit: cover; }
.live-bar { display: flex; align-items: center; gap: .5rem; margin-top: .5rem;
  color: #c9d1d9; font-size: .9rem; }
.live-dot { width: .6rem; height: .6rem; border-radius: 50%; background: #f85149;
  box-shadow: 0 0 0 3px rgba(248,81,73,.25); }
.live-tag { color: #f85149; font-weight: 600; letter-spacing: .06em; }
.live-place { color: #8b949e; }
.credit { color: #6e7681; font-size: .78rem; margin-top: .4rem; }
.grid { display: grid; gap: 1rem; margin-top: 1.5rem;
  grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); }
.card { background: #161b22; border: 1px solid #21262d; border-radius: 12px; padding: 1rem 1.1rem; }
.card .label { color: #8b949e; font-size: .8rem; text-transform: uppercase; letter-spacing: .04em; }
.card .value { font-size: 1.8rem; font-weight: 600; margin-top: .35rem; }
.card .hint { color: #8b949e; font-size: .85rem; margin-top: .25rem; }
.muted .value { font-size: 1rem; font-weight: 500; }
.clocks { list-style: none; margin: 1.5rem 0 0; padding: 0; }
.clock { display: flex; justify-content: space-between; padding: .55rem 0;
  border-bottom: 1px solid #21262d; }
.clock .city { color: #c9d1d9; }
.clock .time { font-variant-numeric: tabular-nums; color: #e6edf3; }
.facts { margin-top: 1.25rem; color: #8b949e; font-size: .9rem; }
.fact { display: flex; gap: .5rem; }
.fact .key { min-width: 5.5rem; color: #6e7681; }
footer { margin-top: 2rem; color: #6e7681; font-size: .8rem; display: flex;
  justify-content: space-between; gap: 1rem; flex-wrap: wrap; }
"""


def _script() -> str:
    """Часы считает браузер по зонам: внешних API и «замороженного» времени нет."""
    return """
(function () {
  var zones = Array.prototype.map.call(document.querySelectorAll("[data-zone]"), function (node) {
    return { node: node, zone: node.getAttribute("data-zone") };
  });
  var TIME = { hour: "2-digit", minute: "2-digit", hour12: false };
  function format(options, now) {
    try {
      return new Intl.DateTimeFormat("en-GB", options).format(now);
    } catch (error) {
      return "--:--";
    }
  }
  function paint() {
    var now = new Date();
    zones.forEach(function (item) {
      item.node.textContent = format(Object.assign({ timeZone: item.zone }, TIME), now);
    });
    var local = document.getElementById("local-time");
    if (local) {
      local.textContent = "Your time " + format(TIME, now) + " \u00b7 " +
        format(Object.assign({ timeZoneName: "short" }, TIME), now);
    }
  }
  paint();
  window.setInterval(paint, 1000);
})();
"""


def _weather_block(weather: WeatherView) -> str:
    if not weather.available:
        return (
            '<div class="card weather muted">'
            '<div class="label">Weather</div>'
            '<div class="value">temporarily unavailable</div>'
            '<div class="hint">the page keeps working without it</div>'
            "</div>"
        )
    parts = [f'<div class="value">{_escape(weather.temperature)}</div>']
    if weather.condition:
        parts.append(f'<div class="hint">{_escape(weather.condition)}</div>')
    details = []
    if weather.wind:
        details.append(f"Wind {_escape(weather.wind)}")
    if weather.humidity:
        details.append(f"Humidity {_escape(weather.humidity)}")
    if details:
        parts.append(f'<div class="hint">{", ".join(details)}</div>')
    if weather.updated:
        parts.append(f'<div class="hint">updated {_escape(weather.updated)}</div>')
    return '<div class="card weather"><div class="label">Weather</div>' + "".join(parts) + "</div>"


def _clock_rows(zones: tuple[tuple[str, str], ...]) -> str:
    if not zones:
        return ""
    rows = [
        '<li class="clock">'
        f'<span class="city">{_escape(label)}</span>'
        f'<span class="time" data-zone="{_escape(zone)}">--:--</span>'
        "</li>"
        for label, zone in zones
    ]
    return '<ul class="clocks">' + "".join(rows) + "</ul>"


def _image_block(image: ImageView) -> str:
    if not image.src:
        return '<div class="hero placeholder" aria-hidden="true"></div>'
    caption = image.attribution or image.source
    credit = f'<div class="credit">{_escape(caption)}</div>' if caption else ""
    return (
        '<figure class="hero">'
        f'<img src="{_escape(image.src)}" alt="{_escape(image.source or "region")}">'
        f"{credit}"
        "</figure>"
    )


def _live_script() -> str:
    """Плеер: сам ходит по боевому семейству /api/media/* тем же почерком, что туннель.

    HLS-библиотека берётся с того же origin (`/assets/hls.min.js`), а не с третьей
    стороны: страница не заводит внешних хостов. Если библиотеки нет — нативный HLS
    (Safari/iOS) всё равно играет, а софa не ломается. Заголовки почерка
    (сессия `X-Upload-Token` и padding `X-Client-Version`) — те же имена, что у
    VLESS-транспорта, чтобы запросы плеера не отличались от боевых.
    """
    return (
        "(function () {"
        "  var video = document.getElementById('live-stream');"
        "  if (!video) { return; }"
        f"  var PLAYLIST = '{MEDIA_PLAYLIST_PATH}';"
        "  var token = Math.random().toString(36).slice(2, 12) + Date.now().toString(36);"
        "  function sign(xhr) {"
        "    xhr.setRequestHeader('X-Upload-Token', token);"
        "    xhr.setRequestHeader('X-Client-Version', 'web/1.0');"
        "  }"
        "  var Hls = window.Hls;"
        "  if (Hls && Hls.isSupported && Hls.isSupported()) {"
        "    var hls = new Hls({ xhrSetup: function (xhr) { sign(xhr); } });"
        "    hls.loadSource(PLAYLIST);"
        "    hls.attachMedia(video);"
        "  } else if (video.canPlayType('application/vnd.apple.mpegurl')) {"
        "    video.src = PLAYLIST;"
        "  }"
        "  var started = video.play();"
        "  if (started && started.catch) { started.catch(function () {}); }"
        "})();"
    )


def _live_player(data: SiteData) -> str:
    """Блок «живой камеры»: то, ради чего страница отдаёт настоящий медиапоток.

    `src` стоит уже в разметке: статичный разбор страницы видит плеер, указывающий на
    медиа-семейство, — это и есть «настоящий медиасервис». JS лишь доустанавливает
    HLS там, где браузер сам её не играет.
    """
    poster = f' poster="{_escape(data.image.src)}"' if data.image.src else ""
    place = _escape(data.place)
    return (
        '<section class="live">'
        '<video id="live-stream" class="live-video" controls autoplay muted playsinline'
        f' preload="none" src="{_escape(MEDIA_PLAYLIST_PATH)}"{poster}></video>'
        '<div class="live-bar"><span class="live-dot"></span>'
        '<span class="live-tag">LIVE</span>'
        f'<span class="live-place">{place} · street camera</span></div>'
        "</section>"
        '<script src="/assets/hls.min.js"></script>'
        f"<script>{_live_script()}</script>"
    )


def _facts(data: SiteData) -> str:
    rows = []
    if data.capital:
        rows.append(
            f'<div class="fact"><span class="key">Capital</span><span class="val">{_escape(data.capital)}</span></div>'
        )
    if data.updated:
        rows.append(
            f'<div class="fact"><span class="key">Updated</span><span class="val">{_escape(data.updated)}</span></div>'
        )
    return '<section class="facts">' + "".join(rows) + "</section>"


def _header(data: SiteData) -> str:
    flag = f'<span class="flag">{_escape(data.flag)}</span>' if data.flag else ""
    return f'<header>{flag}<h1>{_escape(data.place)}</h1><span class="sub">{_escape(data.country)}</span></header>'


def render_page(data: SiteData, *, title: str = DEFAULT_TITLE) -> str:
    """Собрать страницу целиком: разметка, стили и часы внутри одного документа."""
    heading = f"{_escape(title)} — {_escape(data.place)}"
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{heading}</title>
<style>{_styles()}</style>
</head>
<body>
<main>
  {_header(data)}
  {_live_player(data)}
  {_image_block(data.image)}
  <section class="grid">
    {_weather_block(data.weather)}
  </section>
  {_clock_rows(data.zones)}
  {_facts(data)}
  <footer>
    <span>Service status: {_escape(data.status or "operational")}</span>
    <span id="local-time"></span>
  </footer>
</main>
<script>{_script()}</script>
</body>
</html>
"""


__all__ = ["DEFAULT_TITLE", "ImageView", "SiteData", "WeatherView", "render_page"]
