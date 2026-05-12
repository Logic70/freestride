"""
DFD Data Layer (v0.5) — 唯一真相源
布局坐标、边列表、边界定义、威胁映射、stride_analysis、元素描述
所有 DFD 渲染和测试模块从此 import，禁止重复定义。
"""
import json

# ============================================================
# 布局坐标 (W=1300, H=850)
# ============================================================
NODE_POSITIONS = {
    'EE1': (50, 70, 160, 50),    'EE5': (1080, 760, 160, 50),
    'EE2': (1080, 70, 160, 50),  'EE3': (1080, 350, 160, 50),
    'P1':  (380, 50, 130, 130),  'P15': (600, 60, 120, 120),
    'P12': (110, 240, 100, 100), 'P2': (250, 240, 110, 110),
    'P5':  (560, 230, 120, 120), 'P16': (770, 290, 120, 120),
    'P8':  (100, 430, 100, 100), 'P3': (200, 560, 110, 110),
    'P4':  (460, 450, 120, 120), 'P6': (770, 460, 110, 110),
    'DS1': (160, 680, 140, 60),  'DS2': (440, 660, 140, 60),
    'DS3': (640, 660, 140, 60),
}

# ============================================================
# 信任边界 (仅 IPC 边界)
# ============================================================
TRUST_BOUNDARIES = [
    ('TB1', 30, 40, 720, 790, '#dc3545', 'IPC 信任边界'),  # widened to encompass P5(x=620) and P15(x=720)
]

# ============================================================
# 数据流边 (16 条)
# ============================================================
EDGES = [
    ('EE1','P1','IPC API'),('P1','P2','Group'),('P1','P3','Auth'),('P1','P4','Identity'),
    ('P2','P12','Persist'),('P12','DS1','R/W'),('P12','DS2','R/W'),('P3','P5','Protocol'),
    ('P5','EE2','Network'),('P5','P16','Crypto'),('P16','EE3','HUKS'),('P5','P8','SessKey'),
    ('P1','EE5','Callback'),('P1','P15','Perm'),('P5','P6','KeyAgree'),('P8','DS3','Session'),
]

# ============================================================
# 威胁→DFD元素显式映射
# ============================================================
THREAT_DFD_MAP = {
    'T-001':['P5','P3'],'T-002':['P2','P12'],'T-003':['P2','P12'],'T-004':['P3'],
    'T-005':['P1','P16'],'T-006':['P16','EE3'],'T-007':['P1'],'T-008':['P4'],
    'T-009':['P15','P1'],'T-010':['P8'],'T-011':['P6'],'T-012':['P15','EE1'],
    'T-013':['P1','EE1'],'T-014':['P8'],'T-015':['P2','P12'],'T-016':['P2'],
    'T-017':['P1','EE5'],'T-018':['P12','DS1','DS2'],'T-019':['P12','DS1','DS2'],
    'T-020':['P1'],
}

# ============================================================
# 元素中文描述
# ============================================================
ELEMENT_DESC = {
    'EE1':'IPC调用方，通过OHOS IPC调用设备认证服务API',
    'EE2':'远程对等OHOS设备，通过分布式软总线进行PAKE/ISO协议通信',
    'EE3':'HUKS密钥管理，提供硬件支持的密钥生成、存储和密码学运算',
    'EE5':'分布式软总线，消费设备认证会话密钥建立加密通道',
    'P1':'系统能力入口，IPC请求分发、任务调度、事件与进程生命周期管理',
    'P2':'信任群组CRUD：创建、删除、成员增删、查询与回调注册',
    'P3':'群组认证编排，设备间信任认证与会话密钥协商流程控制',
    'P4':'身份服务，凭据操作、监听器分发和会话管理',
    'P5':'协议引擎，PAKE v1/v2(EC-SPEKE/DL-SPEKE)与ISO认证协议实现',
    'P6':'密钥协商SDK，会话密钥协商的会话管理',
    'P8':'会话管理器，认证会话生命周期：创建、状态跟踪、超时与销毁',
    'P12':'数据持久层，群组和凭据的TLV编码存储、读取与查询',
    'P15':'框架层，权限检查、安全标签、任务管理、账户订阅等基础能力',
    'P16':'密码学适配器，封装HUKS和mbedTLS的哈希/签名/验证/密钥协商',
    'DS1':'群组数据存储，持久化信任群组条目、成员列表和元数据',
    'DS2':'凭据数据存储，持久化设备凭据、认证标识符和密钥引用',
    'DS3':'会话缓存，内存维护活跃认证会话与状态',
}

# ============================================================
# 元素代码路径
# ============================================================
ELEMENT_PATHS = {
    'P1':'services/sa/','P2':'services/legacy/group_manager/','P3':'services/legacy/group_auth/',
    'P4':'services/identity_service/','P5':'services/protocol/','P6':'services/key_agree_sdk/',
    'P8':'services/session_manager/','P12':'services/data_manager/','P15':'services/frameworks/',
    'P16':'deps_adapter/key_management_adapter/','DS1':'services/data_manager/group_data_manager/',
    'DS2':'services/data_manager/cred_data_manager/','DS3':'services/session_manager/src/session/',
    'EE1':'interfaces/inner_api/','EE2':'services/protocol/','EE3':'deps_adapter/key_management_adapter/','EE5':'interfaces/',
}

# ============================================================
# stride_analysis 生成
# ============================================================
def generate_stride_analysis(eid):
    """为 DFD 元素生成六维 STRIDE 风险分析"""
    dims = ['Spoofing','Tampering','Repudiation','Information Disclosure','Denial of Service','Elevation of Privilege']
    patterns = {
        ('P1','Spoofing'):('中等','IPC入口依赖进程名白名单+AccessTokenKit验证。若伪造成功可冒充合法调用方。'),
        ('P1','Denial of Service'):('高','任务队列无上限(PushTask)，临界计数器无下界保护。'),
        ('P1','Information Disclosure'):('中等','PRINT_SENSITIVE_DATA输出UDID片段，会话密钥经IPC回传。'),
        ('P12','Tampering'):('高','群组/凭据数据明文TLV存储，无MAC或签名保护。'),
        ('P12','Information Disclosure'):('高','信任凭据和群组数据明文存储，FS读取可泄露令牌和标识。'),
        ('P5','Information Disclosure'):('中等','种子/PSK/nonce释放前未清零，残留于堆内存。'),
        ('P8','Denial of Service'):('中等','全局会话槽位10个，无每来源限制。'),
        ('P15','Spoofing'):('中等','权限检查基于进程名白名单，若进程名可伪造存在绕过风险。'),
        ('P15','Denial of Service'):('中等','任务队列hc_task_thread无容量检查。'),
        ('P4','Denial of Service'):('中等','凭据监听器持锁调用回调，重入可致死锁。'),
        ('P16','Tampering'):('中等','插件dlopen无签名验证。system分区只读提供部分保护。'),
        ('DS1','Tampering'):('高','群组数据明文TLV无完整性保护。'),
        ('DS1','Information Disclosure'):('高','群组条目和成员列表明文存储，可泄露信任拓扑。'),
        ('DS2','Tampering'):('高','凭据数据明文TLV无完整性保护。'),
        ('DS2','Information Disclosure'):('高','设备凭据和认证标识符明文存储。'),
    }
    a = {}
    for dim in dims:
        k = (eid, dim)
        if k in patterns:
            risk, summary = patterns[k]
        else:
            risk, summary = '低', f'{ELEMENT_DESC.get(eid,"")}。此维度未发现显著风险。'
        a[dim] = {'risk': risk, 'summary': summary, 'code_path': ELEMENT_PATHS.get(eid, '')}
    return a

def generate_dfd_index(threats, dfd_data):
    """从威胁列表 + DFD YAML 重建 dfd_index（含stride_analysis + 显式映射）"""
    idx = {}
    for cat in ['external_entities','processes','data_stores']:
        idx[cat] = {}
        for elem in dfd_data.get(cat, []):
            eid = elem['id']
            idx[cat][eid] = {'name': elem.get('name', eid), 'type': cat, 'threats': [], 'threat_count': 0}

    for t in threats:
        for eid in THREAT_DFD_MAP.get(t['id'], []):
            for cat in ['external_entities','processes','data_stores']:
                if eid in idx.get(cat, {}):
                    idx[cat][eid]['threats'].append({
                        'threat_id': t['id'], 'name': t['name'],
                        'severity': t['severity'], 'stride': t['stride_category'],
                        'classification': t['final_classification']
                    })
                    break

    for cat in idx:
        for eid in idx[cat]:
            idx[cat][eid]['threat_count'] = len(idx[cat][eid]['threats'])
            idx[cat][eid]['stride_analysis'] = generate_stride_analysis(eid)

    idx['data_flows'] = {}
    idx['trust_boundaries'] = {}
    for df in dfd_data.get('data_flows', []):
        idx['data_flows'][df['id']] = {'name': f'{df["from"]}→{df["to"]}', 'type': 'data_flows', 'threats': [], 'threat_count': 0, 'stride_analysis': {}}
    for tb in dfd_data.get('trust_boundaries', []):
        idx['trust_boundaries'][tb['id']] = {'name': tb.get('name', ''), 'type': 'trust_boundaries', 'threats': [], 'threat_count': 0, 'stride_analysis': {}}
    return idx
