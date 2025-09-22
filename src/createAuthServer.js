import knexLib from 'knex'
import { Api } from 'hooked-api'
import {
  RestApiPlugin,
  RestApiKnexPlugin,
  ExpressPlugin,
  CorsPlugin,
//  AccessPlugin
} from 'json-rest-api'
import { JwtAuthPlugin } from './jwtAuthPlugin.js'
import { SupabaseAuthPlugin } from './supabaseAuthPlugin.js'
import { GoogleAuthPlugin } from './googleAuthPlugin.js'

const DEFAULT_NAME = 'auth-server'
const DEFAULT_MOUNT_PATH = '/auth'

function ensureKnex(options) {
  if (options.knex) return { instance: options.knex, created: false }
  if (!options.knexConfig) {
    throw new Error('mountAuth: provide either knex or knexConfig')
  }
  return { instance: knexLib(options.knexConfig), created: true }
}

export async function mountAuth(app, options = {}) {
  if (!app || typeof app.use !== 'function') {
    throw new Error('mountAuth: an Express app instance is required')
  }

  const {
    name = DEFAULT_NAME,
    mountPath = DEFAULT_MOUNT_PATH,
    rest = {},
    knexPlugin = {},
    express = {},
    cors,
    auth: authOptions = {},
    google,
    supabase,
    jwt,
    knex,
    knexConfig
  } = options

  const { instance: knexInstance } = ensureKnex({ knex, knexConfig })
  const api = new Api({ name })

  await api.use(RestApiPlugin, rest)
  await api.use(RestApiKnexPlugin, { knex: knexInstance, ...knexPlugin })
  await api.use(ExpressPlugin, { app, mountPath, ...express })

  const restAuthOptions = { ...authOptions }
  if (!restAuthOptions.ownership && jwt?.autoOwnership) {
    restAuthOptions.ownership = { ...jwt.autoOwnership }
  }

	/*
  await api.use(AccessPlugin, restAuthOptions)
*/

  if (cors !== false) {
    const corsOptions = cors === undefined || cors === true ? { credentials: true } : cors
    await api.use(CorsPlugin, corsOptions)
  }

  const hasGoogle = !!google
  const hasSupabase = !!supabase

  if (!hasGoogle && !hasSupabase) {
    throw new Error('mountAuth: provide at least one provider configuration')
  }

  if (hasGoogle) {
    await api.use(GoogleAuthPlugin, google)
  }

  if (hasSupabase) {
    await api.use(SupabaseAuthPlugin, supabase)
  }

  const jwtOptions = { ...jwt }
  delete jwtOptions.autoOwnership
  if (!jwtOptions.defaultProvider) {
    jwtOptions.defaultProvider = hasSupabase ? 'supabase' : hasGoogle ? 'google' : undefined
  }

  await api.use(JwtAuthPlugin, jwtOptions)

  return { api, knex: knexInstance }
}

export async function createAuthApi(options = {}) {
  const {
    name = DEFAULT_NAME,
    rest = {},
    knexPlugin = {},
    auth: authOptions = {},
    jwt = {},
    knex,
    knexConfig
  } = options

  const { instance: knexInstance } = ensureKnex({ knex, knexConfig })
  const api = new Api({ name })

  await api.use(RestApiPlugin, rest)
  await api.use(RestApiKnexPlugin, { knex: knexInstance, ...knexPlugin })
  const restAuthOptions = { ...authOptions }
  if (!restAuthOptions.ownership && jwt.autoOwnership) {
    restAuthOptions.ownership = { ...jwt.autoOwnership }
  }

  await api.use(AccessPlugin, restAuthOptions)

  return { api, knex: knexInstance }
}

export {
  GoogleAuthPlugin,
  SupabaseAuthPlugin,
  JwtAuthPlugin
}
