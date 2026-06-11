import {
  ContentCopyRounded,
  DownloadRounded,
  KeyRounded,
  MoreHorizRounded,
  UploadRounded,
} from '@mui/icons-material'
import {
  Box,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  IconButton,
  List,
  ListItem,
  Menu,
  MenuItem,
  Stack,
  TextField,
  Typography,
} from '@mui/material'
import { useLockFn } from 'ahooks'
import type { MouseEvent, Ref } from 'react'
import { useImperativeHandle, useMemo, useState } from 'react'

import { BaseDialog } from '@/components/base'
import { useProfiles } from '@/hooks/use-profiles'
import { useVerge } from '@/hooks/use-verge'
import {
  deleteAgeKey,
  exportAgeSecretKey,
  generateAgeKeypair,
  importAgeSecretKey,
} from '@/services/cmds'
import { showNotice } from '@/services/notice-service'

export interface AgeKeyManagerViewerRef {
  open: () => void
  close: () => void
}

type Props = { ref?: Ref<AgeKeyManagerViewerRef> }

const summarizePublicKey = (value?: string | null) => {
  if (!value) return 'No public key'
  if (value.length <= 18) return value
  return `${value.slice(0, 8)}...${value.slice(-6)}`
}

export function AgeKeyManagerViewer({ ref }: Props) {
  const { verge, patchVerge, mutateVerge } = useVerge()
  const { profiles } = useProfiles()

  const [open, setOpen] = useState(false)
  const [generateOpen, setGenerateOpen] = useState(false)
  const [importOpen, setImportOpen] = useState(false)
  const [exportOpen, setExportOpen] = useState(false)
  const [generatedName, setGeneratedName] = useState('')
  const [importName, setImportName] = useState('')
  const [importSecret, setImportSecret] = useState('')
  const [exportedSecret, setExportedSecret] = useState('')
  const [menuAnchor, setMenuAnchor] = useState<null | HTMLElement>(null)
  const [activeKeyId, setActiveKeyId] = useState('')

  const ageKeys = verge?.age_keys ?? []
  const profileItems = useMemo(() => profiles?.items ?? [], [profiles?.items])

  const usageMap = useMemo(() => {
    const map = new Map<string, number>()
    for (const item of profileItems) {
      const keyId = item.option?.age_key_id
      if (!keyId) continue
      map.set(keyId, (map.get(keyId) ?? 0) + 1)
    }
    return map
  }, [profileItems])

  const activeKey = ageKeys.find((key) => key.id === activeKeyId) ?? null

  useImperativeHandle(ref, () => ({
    open: () => setOpen(true),
    close: () => setOpen(false),
  }))

  const closeMenu = () => {
    setMenuAnchor(null)
    setActiveKeyId('')
  }

  const onOpenMenu = (
    event: MouseEvent<HTMLElement>,
    keyId?: string | null,
  ) => {
    setMenuAnchor(event.currentTarget)
    setActiveKeyId(keyId ?? '')
  }

  const onGenerate = useLockFn(async () => {
    try {
      const generated = await generateAgeKeypair(
        generatedName.trim() || undefined,
      )
      await patchVerge({
        age_keys: [...ageKeys, generated],
      })
      setGeneratedName('')
      setGenerateOpen(false)
      showNotice.success('Age key pair generated')
    } catch (error) {
      showNotice.error(error)
    }
  })

  const onImport = useLockFn(async () => {
    try {
      const imported = await importAgeSecretKey(
        importName.trim() || undefined,
        importSecret.trim(),
      )
      await patchVerge({
        age_keys: [...ageKeys, imported],
      })
      setImportName('')
      setImportSecret('')
      setImportOpen(false)
      showNotice.success('Age key imported')
    } catch (error) {
      showNotice.error(error)
    }
  })

  const onCopyPublicKey = useLockFn(async () => {
    if (!activeKey?.public_key) return
    await navigator.clipboard.writeText(activeKey.public_key)
    closeMenu()
    showNotice.success('Public key copied')
  })

  const onExport = useLockFn(async () => {
    if (!activeKey?.id) return
    try {
      const secret = await exportAgeSecretKey(activeKey.id)
      setExportedSecret(secret)
      setExportOpen(true)
      closeMenu()
    } catch (error) {
      showNotice.error(error)
    }
  })

  const onDelete = useLockFn(async () => {
    if (!activeKey?.id) return
    try {
      await deleteAgeKey(activeKey.id)
      mutateVerge((prev) => {
        if (!prev) return prev
        return {
          ...prev,
          age_keys: (prev.age_keys ?? []).filter(
            (key) => key.id !== activeKey.id,
          ),
        }
      })
      closeMenu()
      showNotice.success('Age key deleted')
    } catch (error) {
      showNotice.error(error)
    }
  })

  return (
    <>
      <Dialog open={open} onClose={() => setOpen(false)} maxWidth={false}>
        <DialogTitle
          sx={{
            width: 720,
            maxWidth: '92vw',
            boxSizing: 'border-box',
            pb: 1.25,
          }}
        >
          <Box
            sx={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: 2,
            }}
          >
            <Typography variant="h6" sx={{ flexShrink: 0 }}>
              Age Keys
            </Typography>
            <Stack direction="row" spacing={1} sx={{ flexShrink: 0 }}>
              <Button
                variant="contained"
                size="small"
                startIcon={<KeyRounded />}
                onClick={() => setGenerateOpen(true)}
              >
                Generate
              </Button>
              <Button
                variant="outlined"
                size="small"
                startIcon={<UploadRounded />}
                onClick={() => setImportOpen(true)}
              >
                Import
              </Button>
            </Stack>
          </Box>
        </DialogTitle>

        <DialogContent
          sx={{
            width: 720,
            maxWidth: '92vw',
            boxSizing: 'border-box',
            pt: 0,
            pb: 0,
            overflowX: 'hidden',
          }}
        >
          <List disablePadding sx={{ width: '100%' }}>
            {ageKeys.map((key, index) => {
              const usageCount = usageMap.get(key.id) ?? 0
              const usageLabel =
                usageCount === 0 ? 'Unused' : `${usageCount} used`

              return (
                <ListItem
                  key={key.id}
                  divider={index < ageKeys.length - 1}
                  sx={{ px: 0, py: 0, width: '100%' }}
                >
                  <Box
                    sx={{
                      width: '100%',
                      minWidth: 0,
                      display: 'grid',
                      gridTemplateColumns: 'minmax(0,1fr) 160px 72px 32px',
                      alignItems: 'center',
                      columnGap: 2,
                      py: 1.5,
                    }}
                  >
                    <Typography
                      variant="body1"
                      noWrap
                      sx={{
                        minWidth: 0,
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                      }}
                    >
                      {key.name || 'Unnamed key'}
                    </Typography>

                    <Typography
                      variant="body2"
                      color="text.secondary"
                      noWrap
                      sx={{
                        width: 160,
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        fontFamily: 'monospace',
                      }}
                    >
                      {summarizePublicKey(key.public_key)}
                    </Typography>

                    <Typography
                      variant="body2"
                      color="text.secondary"
                      noWrap
                      sx={{ width: 72, textAlign: 'right' }}
                    >
                      {usageLabel}
                    </Typography>

                    <Box
                      sx={{
                        width: 32,
                        display: 'flex',
                        justifyContent: 'flex-end',
                      }}
                    >
                      <IconButton
                        size="small"
                        onClick={(event) => onOpenMenu(event, key.id)}
                      >
                        <MoreHorizRounded fontSize="small" />
                      </IconButton>
                    </Box>
                  </Box>
                </ListItem>
              )
            })}

            {ageKeys.length === 0 && (
              <ListItem sx={{ px: 0, py: 3 }}>
                <Box>
                  <Typography variant="body1">No age keys</Typography>
                  <Typography variant="body2" color="text.secondary">
                    Generate or import a key to get started.
                  </Typography>
                </Box>
              </ListItem>
            )}
          </List>
        </DialogContent>

        <DialogActions
          sx={{
            width: 720,
            maxWidth: '92vw',
            boxSizing: 'border-box',
            px: 3,
            py: 2,
          }}
        >
          <Button variant="contained" onClick={() => setOpen(false)}>
            Close
          </Button>
        </DialogActions>
      </Dialog>

      <Menu anchorEl={menuAnchor} open={!!menuAnchor} onClose={closeMenu}>
        <MenuItem onClick={() => void onCopyPublicKey()}>
          <ContentCopyRounded fontSize="small" sx={{ mr: 1 }} />
          Copy Public Key
        </MenuItem>
        <MenuItem onClick={() => void onExport()}>
          <DownloadRounded fontSize="small" sx={{ mr: 1 }} />
          Export Secret Key
        </MenuItem>
        <MenuItem
          disabled={(usageMap.get(activeKeyId) ?? 0) > 0}
          onClick={() => void onDelete()}
          sx={{ color: 'error.main' }}
        >
          Delete
        </MenuItem>
      </Menu>

      <BaseDialog
        open={exportOpen}
        title="Export Secret Key"
        okBtn="Close"
        disableCancel
        onClose={() => setExportOpen(false)}
        onOk={() => setExportOpen(false)}
      >
        <Box sx={{ mt: 1 }}>
          <Stack
            direction="row"
            justifyContent="space-between"
            alignItems="center"
            sx={{ mb: 1 }}
          >
            <Typography variant="subtitle2">Secret Key</Typography>
            <IconButton
              size="small"
              onClick={async () => {
                await navigator.clipboard.writeText(exportedSecret)
                showNotice.success('Secret key copied')
              }}
            >
              <ContentCopyRounded fontSize="small" />
            </IconButton>
          </Stack>
          <TextField
            fullWidth
            size="small"
            value={exportedSecret}
            multiline
            minRows={3}
            slotProps={{ input: { readOnly: true } }}
          />
        </Box>
      </BaseDialog>

      <BaseDialog
        open={generateOpen}
        title="Generate Age Key"
        okBtn="Generate"
        cancelBtn="Cancel"
        onClose={() => setGenerateOpen(false)}
        onCancel={() => setGenerateOpen(false)}
        onOk={() => void onGenerate()}
      >
        <TextField
          fullWidth
          size="small"
          label="Key Name"
          placeholder="Optional display name"
          value={generatedName}
          onChange={(event) => setGeneratedName(event.target.value)}
          sx={{ mt: 1 }}
        />
      </BaseDialog>

      <BaseDialog
        open={importOpen}
        title="Import Age Key"
        okBtn="Import"
        cancelBtn="Cancel"
        onClose={() => setImportOpen(false)}
        onCancel={() => setImportOpen(false)}
        onOk={() => void onImport()}
      >
        <Stack spacing={2} sx={{ mt: 1 }}>
          <TextField
            fullWidth
            size="small"
            label="Key Name"
            placeholder="Optional display name"
            value={importName}
            onChange={(event) => setImportName(event.target.value)}
          />
          <TextField
            fullWidth
            size="small"
            label="Age Secret Key"
            multiline
            minRows={4}
            value={importSecret}
            onChange={(event) => setImportSecret(event.target.value)}
          />
        </Stack>
      </BaseDialog>
    </>
  )
}
