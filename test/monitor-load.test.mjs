import { expect } from 'chai'
import { getLoadAverages, hasHighLoadAvg } from '../monitor-server.mjs'

describe('The get load average function', () => {
  it('Returns the first 3 floats in /proc/loadavg', async () => {
    expect(await getLoadAverages(() => '1.37 1.30 1.23 2/175 153393')).to.deep.equal([1.37, 1.30, 1.23])
  })
})

describe('The needsReboot function', () => {
  it('Checks if the 5min average is above 1', async () => {
    expect(await hasHighLoadAvg(() => '1.37 1.30 1.23 2/175 153393')).to.be.true
  })
})