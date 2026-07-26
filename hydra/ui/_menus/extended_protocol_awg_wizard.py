"""Controllers for extended transport menus and client status."""
from __future__ import annotations

from hydra.core.state_models import AppState, PluginState
from hydra.services.application import ApplicationService
from hydra.ui.protocol_ui import protocol_menu_title, protocol_status_panel
from hydra.ui.tui import (
    BOLD,
    CYAN,
    DIM,
    GREEN,
    NC,
    PANEL_W,
    RED,
    WHITE,
    YELLOW,
    _bytes_auto,
    clear,
    confirm,
    error,
    info,
    menu,
    panel,
    prompt,
    success,
)

def _awg_generate_wizard(state: AppState, p) -> tuple[str, str | None] | None:
    from hydra.plugins.amneziawg.presets import list_strategies, list_carriers, generate_params, STRATEGIES, CARRIER_OVERRIDES

    # Step 1: Select Strategy
    strategies = list_strategies()
    strat_opts = []
    for idx, s in enumerate(strategies, 1):
        strat_opts.append((str(idx), s["label"], s["description"]))
    strat_opts.append(("0", "Отмена", ""))
    
    choice = menu(strat_opts, "ШАГ 1: ВЫБЕРИТЕ СТРАТЕГИЮ (ТИП СЕТИ)")
    if choice == "0" or not choice.isdigit():
        return None
        
    s_idx = int(choice) - 1
    if not (0 <= s_idx < len(strategies)):
        return None
        
    strategy = strategies[s_idx]["name"]
    carrier = None
    
    # Step 2: Select Carrier if mobile
    if strategy == "mobile":
        carriers = list_carriers(strategy)
        carrier_opts = []
        for idx, c in enumerate(carriers, 1):
            carrier_opts.append((str(idx), c["label"], c["description"]))
        carrier_opts.append(("0", "Отмена", ""))
        
        c_choice = menu(carrier_opts, "ШАГ 2: ВЫБЕРИТЕ ОПЕРАТОРА СВЯЗИ")
        if c_choice == "0" or not c_choice.isdigit():
            return None
            
        c_idx = int(c_choice) - 1
        if not (0 <= c_idx < len(carriers)):
            return None
            
        carrier = carriers[c_idx]["name"]
        if carrier == "generic":
            carrier = None

    # Step 3: Loop for Preview & Regeneration
    while True:
        params = generate_params(strategy=strategy, carrier=carrier)
        
        strat_label = STRATEGIES[strategy].label
        carrier_label = "Универсальный мобильный"
        if carrier:
            carrier_label = CARRIER_OVERRIDES[carrier].label
        elif strategy != "mobile":
            carrier_label = "Не требуется (проводной/stealth)"
            
        lines = [
            f"  Стратегия:  {strat_label}",
            f"  Оператор:   {carrier_label}",
            "",
            f"  Jc   = {params['Jc']:<6}  S1 = {params['S1']:<6}  H1 = {params['H1']}",
            f"  Jmin = {params['Jmin']:<6}  S2 = {params['S2']:<6}  H2 = {params['H2']}",
            f"  Jmax = {params['Jmax']:<6}  S3 = {params['S3']:<6}  H3 = {params['H3']}",
            f"                  S4 = {params['S4']:<6}  H4 = {params['H4']}",
            "",
            f"  I1   = {params['I1'] if params['I1'] else 'Отсутствует'}",
            "",
            f"  {GREEN}ⓘ{NC}  S1({params['S1']}) + 56 = {int(params['S1'])+56} != S2({params['S2']}) — сигнатура WireGuard устранена",
            f"  {GREEN}ⓘ{NC}  Заголовки H1-H4 полностью уникальны и рандомизированы",
        ]
        
        clear()
        panel("🎲 СГЕНЕРИРОВАННЫЕ ПАРАМЕТРЫ ОБФУСКАЦИИ", lines)
        
        confirm_opts = [
            ("1", "✅ Применить эти параметры", "Сохранить и перезапустить туннель с ними"),
            ("2", "🔄 Перегенерировать", "Сгенерировать другие случайные значения"),
            ("0", "❌ Отмена", "Выйти без сохранения"),
        ]
        
        ans = menu(confirm_opts, "ПОДТВЕРЖДЕНИЕ ГЕНЕРАЦИИ")
        if ans == "1":
            return strategy, carrier
        elif ans == "2":
            continue
        else:
            return None
