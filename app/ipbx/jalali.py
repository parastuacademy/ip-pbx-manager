"""Jalali (Persian) calendar helpers — pure Python, no dependencies.

Uses the well-tested jdf (jdf.php) conversion algorithm. The panel shows
dates in Jalali and converts user-entered holiday dates to Gregorian for
Asterisk GotoIfTime conditions.
"""
import time

MONTHS_FA = ("فروردین", "اردیبهشت", "خرداد", "تیر", "مرداد", "شهریور",
             "مهر", "آبان", "آذر", "دی", "بهمن", "اسفند")

WEEKDAYS_FA = ("شنبه", "یکشنبه", "دوشنبه", "سه‌شنبه", "چهارشنبه",
               "پنجشنبه", "جمعه")

# Persian week order (Saturday first) -> Asterisk day names
ASTERISK_DAYS = ("sat", "sun", "mon", "tue", "wed", "thu", "fri")

_MONTH_LEN_J = (31, 31, 31, 31, 31, 31, 30, 30, 30, 30, 30, 29)


def gregorian_to_jalali(gy, gm, gd):
    g_d_m = (0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334)
    gy2 = gy + 1 if gm > 2 else gy
    days = (355666 + (365 * gy) + ((gy2 + 3) // 4) - ((gy2 + 99) // 100)
            + ((gy2 + 399) // 400) + gd + g_d_m[gm - 1])
    jy = -1595 + (33 * (days // 12053))
    days %= 12053
    jy += 4 * (days // 1461)
    days %= 1461
    if days > 365:
        jy += (days - 1) // 365
        days = (days - 1) % 365
    if days < 186:
        jm = 1 + (days // 31)
        jd = 1 + (days % 31)
    else:
        jm = 7 + ((days - 186) // 30)
        jd = 1 + ((days - 186) % 30)
    return jy, jm, jd


def jalali_to_gregorian(jy, jm, jd):
    jy += 1595
    days = (-355668 + (365 * jy) + ((jy // 33) * 8) + (((jy % 33) + 3) // 4) + jd)
    days += sum(_MONTH_LEN_J[:jm - 1])
    gy = 400 * (days // 146097)
    days %= 146097
    if days > 36524:
        days -= 1
        gy += 100 * (days // 36524)
        days %= 36524
        if days >= 365:
            days += 1
    gy += 4 * (days // 1461)
    days %= 1461
    if days > 365:
        gy += (days - 1) // 365
        days = (days - 1) % 365
    gd = days + 1
    leap = (gy % 4 == 0 and gy % 100 != 0) or (gy % 400 == 0)
    month_lens = (0, 31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
    gm = 12
    for i in range(1, 13):
        if gd <= month_lens[i]:
            gm = i
            break
        gd -= month_lens[i]
    return gy, gm, gd


def format_jalali_date(gy, gm, gd):
    jy, jm, jd = gregorian_to_jalali(gy, gm, gd)
    return f"{jy:04d}/{jm:02d}/{jd:02d}"


def format_jalali_long(gy, gm, gd):
    jy, jm, jd = gregorian_to_jalali(gy, gm, gd)
    return f"{jd:02d} {MONTHS_FA[jm - 1]} {jy:04d}"


def jalali_str_to_gregorian(text):
    """'1404/08/16' or '1404-08-16' -> (gy, gm, gd) or None."""
    import re
    m = re.fullmatch(r"(\d{4})[/\-.](\d{1,2})[/\-.](\d{1,2})", (text or "").strip())
    if not m:
        return None
    jy, jm, jd = int(m.group(1)), int(m.group(2)), int(m.group(3))
    if not (1 <= jm <= 12 and 1 <= jd <= 31):
        return None
    gy, gm, gd = jalali_to_gregorian(jy, jm, jd)
    return (gy, gm, gd)


def gregorian_to_jalali_str(gdate):
    """'2026-11-07...' -> '1405/08/16' or ''."""
    import re
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})", (gdate or "").strip())
    if not m:
        return ""
    return format_jalali_date(int(m.group(1)), int(m.group(2)), int(m.group(3)))


def today_jalali():
    t = time.localtime()
    return gregorian_to_jalali(t.tm_year, t.tm_mon, t.tm_mday)


def weekday_fa_name(asterisk_day):
    return WEEKDAYS_FA[ASTERISK_DAYS.index(asterisk_day)] if asterisk_day in ASTERISK_DAYS else asterisk_day


FA_DIGITS = str.maketrans("0123456789", "۰۱۲۳۴۵۶۷۸۹")


def fa_digits(text):
    """Latin digits -> Persian digits (for UI display)."""
    return str(text).translate(FA_DIGITS)


def jalali_datetime(value):
    """'2026-11-07 10:30:00' (CDR start) -> '1405/08/16 10:30' in Persian digits."""
    import re
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})", str(value or ""))
    if not m:
        return fa_digits(value)
    gy, gm, gd = int(m.group(1)), int(m.group(2)), int(m.group(3))
    hh, mm = m.group(4), m.group(5)
    return fa_digits(f"{format_jalali_date(gy, gm, gd)} {hh}:{mm}")
