<!--
  - SPDX-FileCopyrightText: 2024 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->
<template>
	<FileListFilter class="file-list-filter-type"
		:is-active="isActive"
		:filter-name="t('files', 'Type')"
		@reset-filter="resetFilter">
		<template #icon>
			<NcIconSvgWrapper :path="mdiFileOutline" />
		</template>
		<NcActionButton v-for="fileType of typePresets"
			:key="fileType.id"
			type="checkbox"
			:model-value="selectedOptions.includes(fileType)"
			@click="toggleOption(fileType)">
			<template #icon>
				<NcIconSvgWrapper :svg="fileType.icon" />
			</template>
			{{ fileType.label }}
		</NcActionButton>
	</FileListFilter>
</template>

<script lang="ts">
import type { PropType } from 'vue'
import type { ITypePreset } from '../../filters/TypeFilter.ts'

import { mdiFileOutline } from '@mdi/js'
import { translate as t } from '@nextcloud/l10n'
import { defineComponent } from 'vue'

import NcActionButton from '@nextcloud/vue/components/NcActionButton'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import FileListFilter from './FileListFilter.vue'

export default defineComponent({
	name: 'FileListFilterType',

	components: {
		FileListFilter,
		NcActionButton,
		NcIconSvgWrapper,
	},

	props: {
		presets: {
			type: Array as PropType<ITypePreset[]>,
			default: () => [],
		},
		typePresets: {
			type: Array as PropType<ITypePreset[]>,
			required: true,
		},
	},

	setup() {
		return {
			mdiFileOutline,
			t,
		}
	},

	data() {
		return {
			selectedOptions: [] as ITypePreset[],
		}
	},

	computed: {
		isActive() {
			return this.selectedOptions.length > 0
		},
	},

	watch: {
		/** Reset selected options if property is changed */
		presets() {
			this.selectedOptions = this.presets ?? []
		},
		selectedOptions(newValue, oldValue) {
			if (this.selectedOptions.length === 0) {
				if (oldValue.length !== 0) {
					this.$emit('update:presets')
				}
			} else {
				this.$emit('update:presets', this.selectedOptions)
			}
		},
	},

	mounted() {
		this.selectedOptions = this.presets ?? []
	},

	methods: {
		resetFilter() {
			this.selectedOptions = []
		},

		/**
		 * Toggle option from selected option
		 * @param option The option to toggle
		 */
		toggleOption(option: ITypePreset) {
			const idx = this.selectedOptions.indexOf(option)
			if (idx !== -1) {
				this.selectedOptions.splice(idx, 1)
			} else {
				this.selectedOptions.push(option)
			}
		},
	},
})
</script>

<style>
.file-list-filter-type {
	max-width: 220px;
}
</style>
