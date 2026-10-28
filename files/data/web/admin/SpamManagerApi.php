<?php
$sm_had_token=isset($_POST['csrf_token']) && is_string($_POST['csrf_token']);
require_once $_SERVER['DOCUMENT_ROOT'].'/inc/prerequisites.inc.php';
require_once $_SERVER['DOCUMENT_ROOT'].'/inc/spammanager.inc.php';
header('Content-Type: application/json; charset=utf-8');header('Cache-Control: no-store');header('X-Content-Type-Options: nosniff');
function sm_reply(int $code,array $data): void {
  http_response_code($code);$data['csrf_token']=$_SESSION['CSRF']['TOKEN'] ?? '';echo json_encode($data,JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);exit;
}
if(($_SESSION['mailcow_cc_role'] ?? '')!=='admin' || !empty($_SESSION['mailcow_cc_api']) || ($_SESSION['SESS_REMOTE_UA'] ?? null)!==($_SERVER['HTTP_USER_AGENT'] ?? ''))sm_reply(403,['ok'=>false,'message'=>'請使用 Mailcow 管理員登入。']);
try{
  if($_SERVER['REQUEST_METHOD']==='GET'){
    $op=$_GET['op'] ?? 'state';
    if($op==='state')$data=sm_state();
    elseif($op==='history'){$history=sm_controller('history');$data=['rows'=>array_slice($history['rows'] ?? [],0,100)];}
    elseif($op==='rejected'){$data=['rows'=>sm_rejected(),'notify'=>sm_rejected_notify()];}
    elseif($op==='outbound'){$data=['rows'=>sm_outbound(),'notify'=>sm_outbound_notify()];}
    elseif($op==='customizations'){$data=['items'=>sm_customizations()];}
    elseif($op==='update_status'){$data=sm_update_status();}
    else throw new InvalidArgumentException('未知的讀取操作。');
    sm_reply(200,['ok'=>true,'data'=>$data]);
  }
  if($_SERVER['REQUEST_METHOD']!=='POST')sm_reply(405,['ok'=>false,'message'=>'僅支援 GET 與 POST。']);
  // Native session_check already validates/removes the submitted token and rotates it.
  if(!$sm_had_token || isset($_POST['csrf_token']) || !isset($_POST['op'],$_POST['payload']))sm_reply(403,['ok'=>false,'message'=>'登入驗證已更新，請重試。']);
  $p=json_decode($_POST['payload'],true,64,JSON_THROW_ON_ERROR);if(!is_array($p))throw new InvalidArgumentException('資料格式不正確。');
  $lock=fopen(sys_get_temp_dir().'/mailcow-spammanager.lock','c');
  if(!$lock || !flock($lock,LOCK_EX | LOCK_NB))sm_reply(409,['ok'=>false,'message'=>'另一筆設定正在儲存，請稍後再試。']);
  $result=sm_mutate((string)$_POST['op'],$p);
  logger();unset($_SESSION['return']);
  flock($lock,LOCK_UN);fclose($lock);
  sm_reply(200,['ok'=>true,'data'=>$result,'message'=>$result['message']]);
}catch(InvalidArgumentException | JsonException $e){logger();unset($_SESSION['return']);sm_reply(422,['ok'=>false,'message'=>$e->getMessage()]);}
catch(Throwable $e){error_log('SpamManager: '.$e->getMessage());logger();unset($_SESSION['return']);sm_reply(503,['ok'=>false,'message'=>$e instanceof RuntimeException && !($e instanceof PDOException)?$e->getMessage():'設定操作失敗，請重新整理確認。']);}
