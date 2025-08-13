import fs from 'fs/promises'

export async function readLoadAverages() {
  return (await fs.readFile('/proc/loadavg')).toString()
}

export async function getLoadAverages(read = readLoadAverages) {
  return (await read()).split(' ').slice(0, 3).map(avg => parseFloat(avg))
}

export async function hasHighLoadAvg(read = readLoadAverages) {
  const averages = await getLoadAverages(read)
  return averages[1] >= 1
}