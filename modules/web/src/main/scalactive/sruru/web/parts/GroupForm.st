<script lang="scala">
import sruru.shared.*
import sruru.web.*

// グループを作るモーダル（基本の項目だけ. 作った後はグループの画面で、メンバーやポリシーの上書きを設定する）.
case class Props(groups: List[GroupDto], onSaved: GroupDto => Unit, onClose: Unit => Unit)
</script>

<template>
  <Modal :onClose="_ => props.onClose(())" :wide="true">
    <h2>グループを作る</h2>
    <GroupEditor :group="None" :groups="props.groups" :withPolicy="false" :onSaved="props.onSaved" :onCancel="Some(props.onClose)" />
  </Modal>
</template>
