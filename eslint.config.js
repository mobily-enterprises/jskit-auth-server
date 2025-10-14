import neostandard from 'neostandard'

export default [
  ...neostandard({ ignores: ['node_modules/**'] }),
  {
    rules: {
      camelcase: 'off',
      'no-empty': 'off',
      'no-unused-vars': 'off'
    }
  }
]
