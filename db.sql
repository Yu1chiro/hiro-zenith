-- 1) Tabel utama: kegiatan harian ------------------------------------
CREATE TABLE IF NOT EXISTS activities (
  id             INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  title          VARCHAR(255) NOT NULL CHECK (char_length(btrim(title)) > 0),
  activity_date  DATE         NOT NULL,
  notes          TEXT,
  created_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  updated_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Index untuk query per-tanggal / per-minggu / per-bulan
CREATE INDEX IF NOT EXISTS idx_activities_date
  ON activities (activity_date, id);

-- 2) Pengaturan hari kerja (satu baris saja) --------------------------
--    Default: Senin–Jumat. Sabtu & Minggu bersifat opsional.
CREATE TABLE IF NOT EXISTS work_settings (
  id                SMALLINT    PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  include_saturday  BOOLEAN     NOT NULL DEFAULT FALSE,
  include_sunday    BOOLEAN     NOT NULL DEFAULT FALSE,
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO work_settings (id) VALUES (1)
ON CONFLICT (id) DO NOTHING;

-- 3) (Opsional) Cek hasil ---------------------------------------------
-- SELECT * FROM work_settings;
-- SELECT * FROM activities ORDER BY activity_date, id;