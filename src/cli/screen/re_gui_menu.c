// re_gui_menu.c - dropdowns for the menu row.
// Module: cli (C11).
// Owns: the item lists and the click that runs one.
// Depends: re_gui_menu.h, re_screen, re_ui.
#include "cli/screen/re_gui_menu.h"

#include "utils/tui/re_tui.h"

typedef struct {
    re_gui_menu_ctx_t *c;
    re_ui_t *ui;
    int menu;
    int item;
} menu_arg_t;

static menu_arg_t g_arg[16];
static size_t g_narg;

// True when zone is this menu's toolbar title or one of its open dropdown rows.
static bool menu_owns_zone(const re_gui_menu_ctx_t *c, int menu, uint8_t zone) {
    uint8_t z0;
    uint8_t n;
    if (!c || zone == RE_SCREEN_ZONE_NONE)
        return false;
    if (zone == (uint8_t)(c->bar + menu))
        return true;
    if (!c->open || *c->open != menu || !c->zone || !c->nitems)
        return false;
    z0 = *c->zone;
    n = *c->nitems;
    if (z0 == RE_SCREEN_ZONE_NONE || n == 0)
        return false;
    return zone >= z0 && zone < (uint8_t)(z0 + n);
}

static const char *const kEdit[] = {"Next function", "Previous function"};
static const char *const kJump[] = {"First function", "Page top"};
static const char *const kSearch[] = {"Functions", "Imports", "Exports"};
static const char *const kOptions[] = {"Color", "Syntax"};
static const char *const kHelp[] = {"Keys", "Quit"};

static const char *const *items_of(int menu, size_t *n) {
    *n = 0;
    if (menu == 1) {
        *n = 2;
        return kEdit;
    }
    if (menu == 2) {
        *n = 2;
        return kJump;
    }
    if (menu == 3) {
        *n = 3;
        return kSearch;
    }
    if (menu == 4) {
        *n = 2;
        return kOptions;
    }
    if (menu == 5) {
        *n = 2;
        return kHelp;
    }
    return NULL;
}

static uint16_t menu_x(int menu) {
    static const char *const kBar[] = {"File", "Edit", "Jump", "Search", "Options", "Help"};
    uint16_t x = 1;
    int i;
    for (i = 0; i < menu && i < 6; i++)
        x = (uint16_t)(x + 1u + re_tui_cols(kBar[i]) + 2u + 1u);
    return x;
}

static void run_item(re_gui_menu_ctx_t *c, int menu, int item) {
    if (menu == 1 && item == 0 && c->sel && *c->sel + 1u < c->nfunc)
        (*c->sel)++;
    if (menu == 1 && item == 1 && c->sel && *c->sel)
        (*c->sel)--;
    if (menu == 2 && item == 0 && c->sel)
        *c->sel = 0;
    if (menu == 2 && item == 1 && c->page_off)
        *c->page_off = 0;
    if (menu == 3 && c->tab && item >= 0 && item < 3) {
        static const size_t kTab[] = {0, 4, 5};
        if (kTab[item] < c->ntab)
            *c->tab = kTab[item];
    }
    if (menu == 4 && item == 0 && c->color)
        *c->color = !*c->color;
    if (menu == 4 && item == 1 && c->syntax)
        *c->syntax = !*c->syntax;
    if (menu == 5 && item == 0 && c->console)
        re_console_push(c->console, "q quit  tab focus  arrows select  left/right page");
    if (menu == 5 && item == 1 && c->quit)
        *c->quit = true;
    if (c->repaint)
        *c->repaint = true;
    if (c->open)
        *c->open = -1;
}

static void on_bar(void *user) {
    menu_arg_t *a = user;
    if (!a || !a->c || !a->c->open)
        return;
    *a->c->open = *a->c->open == a->menu ? -1 : a->menu;
    if (a->c->repaint)
        *a->c->repaint = true;
}

static void on_hover(void *user, bool over) {
    menu_arg_t *a = user;
    if (!a || !a->c || !a->c->open || !a->ui)
        return;
    if (over) {
        if (*a->c->open == a->menu)
            return;
        *a->c->open = a->menu;
        if (a->c->repaint)
            *a->c->repaint = true;
        return;
    }
    // Leave: set_hot already stored the new hot zone. Stay open while the pointer
    // is still on this title or its dropdown; dismiss only when it left the menu.
    if (*a->c->open != a->menu)
        return;
    if (menu_owns_zone(a->c, a->menu, a->ui->hot))
        return;
    *a->c->open = -1;
    if (a->c->repaint)
        *a->c->repaint = true;
}

static void on_item(void *user) {
    menu_arg_t *a = user;
    if (a && a->c)
        run_item(a->c, a->menu, a->item);
}

static menu_arg_t *arg(re_gui_menu_ctx_t *c, re_ui_t *ui, int menu, int item) {
    menu_arg_t *a;
    if (g_narg >= 16)
        return NULL;
    a = &g_arg[g_narg++];
    a->c = c;
    a->ui = ui;
    a->menu = menu;
    a->item = item;
    return a;
}

void re_gui_menu_draw(re_screen_t *s, re_gui_menu_ctx_t *c) {
    size_t n = 0, i;
    const char *const *items;
    uint16_t x, w = 0;
    if (!s || !c || !c->open || *c->open < 1)
        return;
    items = items_of(*c->open, &n);
    if (!items)
        return;
    x = menu_x(*c->open);
    for (i = 0; i < n; i++)
        if (re_tui_cols(items[i]) > w)
            w = (uint16_t)re_tui_cols(items[i]);
    if (c->zone)
        *c->zone = RE_SCREEN_ZONE_NONE;
    if (c->nitems)
        *c->nitems = 0;
    for (i = 0; i < n && (uint16_t)(2u + i) < s->rows; i++) {
        uint8_t zone = re_screen_zone(s);
        if (c->zone && *c->zone == RE_SCREEN_ZONE_NONE)
            *c->zone = zone;
        if (c->nitems)
            (*c->nitems)++;
        re_screen_fill(s, (uint16_t)(1u + i), x, (uint16_t)(w + 2u), 1, " ", (uint8_t)RE_ST_LABEL,
                       zone);
        re_screen_put_run(s, (uint16_t)(1u + i), (uint16_t)(x + 1u), (uint16_t)(x + 1u + w),
                          items[i], (uint8_t)RE_ST_LABEL, zone);
    }
}

void re_gui_menu_bind(re_ui_t *u, re_gui_menu_ctx_t *c) {
    int menu;
    size_t i, n = 0;
    g_narg = 0;
    if (!u || !c || c->bar == RE_SCREEN_ZONE_NONE)
        return;
    for (menu = 1; menu <= 5; menu++) {
        menu_arg_t *a = arg(c, u, menu, -1);
        if (a)
            re_ui_bind(u, (uint8_t)(c->bar + menu), on_bar, on_hover, a);
    }
    if (!c->open || *c->open < 1 || !c->zone || *c->zone == RE_SCREEN_ZONE_NONE)
        return;
    items_of(*c->open, &n);
    for (i = 0; i < n && i < (c->nitems ? *c->nitems : 0u); i++) {
        menu_arg_t *a = arg(c, u, *c->open, (int)i);
        if (a)
            re_ui_bind(u, (uint8_t)(*c->zone + i), on_item, on_hover, a);
    }
}
