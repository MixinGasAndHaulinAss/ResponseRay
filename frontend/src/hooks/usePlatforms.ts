import { useQuery } from '@tanstack/react-query'
import { api, PlatformInfo } from '../lib/api'

export function usePlatforms(siteId: string | undefined) {
  const { data, isLoading, error } = useQuery({
    queryKey: ['platforms', siteId],
    queryFn: () => api.getPlatforms(siteId!),
    enabled: !!siteId,
    staleTime: 30000,
  })

  const platforms = data || []

  return {
    platforms,
    isLoading,
    error,
    hasPlatform: (platform: string) => platforms.some((p: PlatformInfo) => p.platform === platform),
    hasAnyPlatform: (...platformList: string[]) => platforms.some((p: PlatformInfo) => platformList.includes(p.platform)),
  }
}
