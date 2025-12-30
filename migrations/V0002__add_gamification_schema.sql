-- Gamification and Finance Schema
-- Supports badges, user progression (XP/Level), and travel budgeting.

-- Enums
DO $$ BEGIN
    CREATE TYPE badge_rarity AS ENUM ('common', 'rare', 'epic', 'legendary');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
    CREATE TYPE budget_category AS ENUM ('accommodation', 'transport', 'food', 'activities', 'shopping', 'other');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- User Gamification Stats (One-to-One with users)
CREATE TABLE IF NOT EXISTS user_gamification (
    user_id         UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    level           INTEGER NOT NULL DEFAULT 1,
    xp_current      INTEGER NOT NULL DEFAULT 0,
    xp_next_level   INTEGER NOT NULL DEFAULT 100,
    streak_days     INTEGER NOT NULL DEFAULT 0,
    last_activity_at TIMESTAMPTZ,
    total_trips     INTEGER NOT NULL DEFAULT 0,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Badges (Metadata definitions)
CREATE TABLE IF NOT EXISTS badges (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug            TEXT NOT NULL UNIQUE,
    name            TEXT NOT NULL,
    description     TEXT,
    image_url       TEXT,
    rarity          badge_rarity NOT NULL DEFAULT 'common',
    xp_reward       INTEGER NOT NULL DEFAULT 10,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- User Badges (Earned badges)
CREATE TABLE IF NOT EXISTS user_badges (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    badge_id        UUID NOT NULL REFERENCES badges(id) ON DELETE CASCADE,
    earned_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_user_badge UNIQUE (user_id, badge_id)
);

CREATE INDEX IF NOT EXISTS idx_user_badges_user ON user_badges(user_id);
CREATE INDEX IF NOT EXISTS idx_user_badges_earned_at ON user_badges(earned_at);

-- Trip Budgets
CREATE TABLE IF NOT EXISTS trip_budgets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    trip_name       TEXT NOT NULL,
    total_budget    DECIMAL(10, 2) NOT NULL,
    currency        VARCHAR(3) NOT NULL DEFAULT 'USD',
    start_date      DATE,
    end_date        DATE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_trip_budgets_user ON trip_budgets(user_id);

-- Budget Expenses
CREATE TABLE IF NOT EXISTS budget_expenses (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    trip_budget_id  UUID NOT NULL REFERENCES trip_budgets(id) ON DELETE CASCADE,
    category        budget_category NOT NULL DEFAULT 'other',
    amount          DECIMAL(10, 2) NOT NULL,
    description     TEXT,
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_budget_expenses_trip ON budget_expenses(trip_budget_id);
CREATE INDEX IF NOT EXISTS idx_budget_expenses_category ON budget_expenses(category);
