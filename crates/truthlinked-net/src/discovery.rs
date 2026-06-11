//! Peer Discovery and Bootstrap System

use serde::{Deserialize, Serialize};
use truthlinked_governance::params as gp;

// Repo-local validator bootstrap identities. These correspond to the default
// three-validator devnet defined in genesis.rs.
const VALIDATOR1_DILITHIUM_PUBKEY: &str = "3ca83f6fc32cc546a55d90f16fa5520e4c0c37e4487d8331ce9c666e583f88a13f85286d919e08ad1291eff5f4e6d5ee7b3633c851932742c70901eec4bc3b4036b370ef4820c5ee194ffa1469ded78d8ed7274c74ad6c56b8f74dce5560798e00f0ef1da8c59222c0ae6dbbd2ff3fe37ade4d6d4f58e1aa1b7f7d99ef6d7d0646933598954093689997d10ae4d4ef7a0282ad97615ee5d5044cfa2b076ec4c4daf6275d544de483afe063101d74b0ce101dfb6e418d542dae3a7899588ef430bb745abd5acd61006d58e6a103cb5eee517ca126f9663409466bfc00306d19034f239e5ba0cbdf9bd6f2f923a6da243344061be06178e5a4b4b81505555cdb6900ee741dc6a275b6a6da9f2f52515e90f09684d035f7e193fffcccb16859cba0ca4bd72f89964b4bbb8b291d79a5dced8e100b481889df8d82cb42cbf518be314166cb5d486febdcb3581e0907d8eea8b14bf82a13d20346ecf1bce21ff7e6bf3c5afa2b57dc7b128c7fd344fc660285cb764799ae559bb6281e9454b849ed0c0ac88566d7cc6b9f7eee4d0ad21797c492fb7d8b976da179fbaa7a234d3dd2e59c716eb921c3c0fff53167b6110abb22c0f8cc304cdcded5a57dfba849b8f7564790c755386b05147b8021ea5623609a91e0ccfb520f47efb0d741d7f8fde4c73807cbe18d3a316b8220706ac3500254f672d17ec9b5d4d35b3b7a141bd8f981f480e17acf2e7a70244482bb6490b6531be21447f9eb09554052bae32bf336b5465f25d4f667d006bceaf8af735259d2b273d3803d31a810c29e8f5d5dc33aa543d98e70a4dc2d9f5a66c5dd49c9411e43ae74a3adf681bd8ce5c02e2fef7f697d4c87d2fec861295970f37e84ec2713e47c8c84d448444ceea384ea045530d50056120dd712cef82d3ca551a93f748010fd26184e95626e4b12d0436478aa7676d37dc7c3581fb3ab6e3e9d4457e9160cc65cc1fc1f58fb099cd2fb27af9db334c7f63631a76f7cbf39c812e10df1b1edf770ab49f04f79b9c56a39808d4392b566ae8d71b1b71671a02bb5fb026cdc2ed9f945e0f22a30a493b52a0435637a2633aa48bf0adb2d0563a6ef5361108902eeb86794fb129dcfa42e59f53a8bf39d6b76f91499652dd30e9dfed5ea5d36a4cf8e05b1178e015ae2c0c73e9ec5c38645c19f316acaf0b5247e32a9cc8556b97bdfa892d5fe6f958e7ba38e2df89854e851c176f4ec1c0769bf9d19ba9c693c3220d655524528403eec70708b77161b78a97961d94b91a5a8f125ad0b0ab9c3e11f6b5fa22599e80b62ec1b04562cb4bfbb1aa838603448dd46e79814669f091863484ce523dab044c7a6d61b74429bbb2649823b83bd3072cd1f6ad4f6b2a1f6ed1be7c899afe34d0f263b61f28d2bfd6ff457258c06b3f906eeea42d152b959e81b60e8075b782d066a8e7533f58c07c40645f5dd159bfec843e0a1bcff98c91b4f266e057fa8d9f5fb1bedddfc807275371c0c3d40004625c38b23771a19a3038c9b7ea54c8da069ff6e2be84aa62c6532140e1ef8ab657beea6c86e254a2646e34b8549ddb4cb6876c085e9e6b2d95efa67082cfa12c490b6905d30231abf91e145c9f30e34ee6f90526bcdeb6b78e095f072b7949462e473fbc50a8054d2b5974dd749918e6e908a652c5a8b7068d56bb164fdb2b015f2b1e74cda22b3cf21ddfff594c78be8828c707310b3d8f72639ee7f4241143bed761d9f906957f66216ad884532609ca99e45796cbf45489e2d50721b39e92c254749d8d174624ae5324ec1fd276fb62d155f33cd61a912b398d7f4fe2dc4638506288ca3876e75c5b6a6d9cc02a3ff8c3c2668ba42375e08f35480e43864aa7b3676b62eb0002be5593b58bbaf96a03523aaff808d343272147e0c897a26e07676ab170dd1c15353da3413b13c6f33bed3e72a69bfc38b1ac6f40a24bf5d7c748";
const VALIDATOR2_DILITHIUM_PUBKEY: &str = "fa78171e55c878b95a85fc46e03e92023073c7c07b89499014a85d653e9a5d64152ccd75c3fb14871f639bcb13c084e3325a870f9aca81f6355e823eaff52ce4d1aaf4d0018dc3b34707e7851ccf01cd4878c33ebfb2c4463c5351620558b726c815c707467dbeb5733cc76a269b3625ee9d19c72084e27c5c9dba6da4552a329c5326711e2ecc43cca435bbf4c8a488d2d374d62bf79194752c8a5c97506532f56c57e3ff8d359955bfeda31ec3fb1d5b984255a851fd922ee88a4bfabfd33f84db7798b905f054a89fbd1a1de907d01da25f7b8aa6d1ac83db028d459611b3a9643e3a27612f4d37947362a00f63ab4db55291a20cb01c1416f03c86bad55d71cc0c44cb9b8d41887b8c825fabd0bda4d9389dcc8aa0bb7a0e237cf755b38d4785eb69397a4a7d599d556976f549a8e4980c77f6a313cc7ad0ec3ba3cd3ccaf8926d0c3e244da1d76ec31cf01c2ed7602437edaa21fbf876e0e1d928d93848dcdbfb194fc5527dbeca4d199a625f837cb6080a7df060e9e5de5a7782c8b86422d82b2d7c263ccf9fc22c9cd6677729de76c2a0cce388f974a1202b6a338ba208b23a65c45f3d1065e223284a4615c018a3a16c5c1bd68a4ab64e91b00db68108fd0ef049fcbab293204900433f614fe6edd832b84e5e0aa6c7c36b294155f7eef4c8dbfc28bbd0d6a910f94c22bff344687465ec9c86a3b083813ba1ba4a11d86fdf69c6caff4ac5bbf64e840e99d514d45599189f9bab129446a4896ec87ff1e4343001165dc05598f50722492bc2a964e4b9b34764f628bfe9d4618b62833675c0fcdecb9651e03277b84c5fce38dc2a105455d5f208f4ad298cce0c454c70081b209c151cd362a3b90b7ca03de6cef2b39619e469a560cb09ae7d44f4651436acbf08ed2b4a317e4faf7c656d55c4e8f4d196d4859a3aa7c359069be224868cee98dd7df19b37d37cf4eb56b75fcafef9354b3a734aa0cd208cd16ba85b8c2ae5fefc3ef69033c6db7c74559280f7885d879b8eb14fb6d6ce63c7a6d0d3b437eb6575e7422abbeccd9bad129519ecb23c59b446175783de6f6ee323c0d9e982a3c4a8ddc2d99f377ca79ea0bb24ed2053939e804823e645c7f421d6ca908021d9b29a0f812ef4342e0cfac556e203757bae822cf849b4a240eb44c89cb312440e40b229e463b084b68131ea2c5a1b5a450108c10f93643a4f1c46625db4b6c88792f5a85ba251adebf315b5a906e9c93e942c78f540306f3d176458ebc7d4bc146cfc7c5be40c590d473496d43c4f25531a0ad6bc40d9de11974b1b5fb4f30cb68f256c41bb146435b168eced889fc09430edc1b2f91b517acb0ab253c3b7d18ccccb626d996ab84b03611a2a0d80b8ec0dd408da8a7870e255678eaae269d161b47060382f0d40ac2d4d1e8708c8040a29313758fc1f543769d7e8512c07ea196c2853865b54cfcafc2f697a165e9cdb54b0dec35bffa1e0744e7d7e637641124d58fc96e8aa99e39c7b1354df5fedb64ea0754f47b962014b92fef7a3c4dc2ae1b7f4bd037c454e54dbe191e1b5dac04370080b407b486bab60fe3911fdeb5d147d18a65c20244da4ff3ab94cb7fefdded8d822b97e4d746b4a8331e8dd6d50592da9e3fd4e9c272d448b429093cb7a6e6729175f6fdd1b41b612ad2fc163eff249b7a2f89c2f6e11fc6f2f8a804e07cf08133f2d698e922ed26a3b94b8f937b939082d07c3c528106a257f4b9dbc64edade854a7c0fbada12cfb454ff91be05804f1b962c0b836a27e7c88d91437137577740130f8434aea9ac4ee63294b27a8f167e82420b16a07701e35a9f5e317dd70a35efb461206268dc65ffc7e8e063dfe1bacdb73b979e29e178118f4015060e9e6ec737c449f687443bbfc314876309ddc5f4c47cbb2bc2cacffe74e0d400842f01af3f6358d5fe24b60e4a02b720bd6e24a19576a457";
const VALIDATOR3_DILITHIUM_PUBKEY: &str = "0ecaf9a0875e29d8679935919aebdd48eea3f8ae3f01f56307df0d6d7b1b20796f657c01c82d63bd0b687afd464de7a1527e173e6c986b1cee21f98a847fe202aa58bc8e58c3e92c3896f8dc764de55a353467e2b6b87cf23ec5e0afaa867d090a4c97a49f424e1a39f3aa728b6accc550c182925f51fb1c484c7562b7be05a1d96c3837693f7b0617c91107eb70ac87b913fb35a6fff3ee27ba326b8f6e7339cbacab459ef3ccd46303fcf702b847bc317f7bfd28a0a92735a186648396ae11a7e35fe0cd92404ede4753483cc128847dc9bdb09de475b40b26b2314ad835317a8dd8c3f7e60f86d74c4b196da1747f9261256929b98a8a3c04e9d2b3b4b58a01d8ee60f763d2e439c54fb5e02e25c781b91504675dcc0f8668475504b46d629ffcc6677946969fd430ca1c52d96d5ed7c2d06c90c5c8fd635ba0e1b87b608300c77d93c528edbf837d21faa842955be6dda6a177f8a268baf9f819d2a58f190b4e8000f9fdb7eefd2de44eda2bc81c68620caf5977dfd15130921f1f61c346e91ce326a13ed0839ef92e9728e5aeb6b55ec09154c15c181d41395918b314fc0ae3786a072c8c55e412186537424a716ca8763e392b129a7f641e03f8ebe81138c1370718b0c4edf4bb2eebc196ff1e07ff8bfc79fbfd19d10ec3abc92e5d27b87de1aac4496fa375926ed1184c9be38a7ef4d19d4d6d651daaae3c86a6db4e9106aa1c3c66e2d2e3ef3aee9d0acbd5fb70a5fe8812405236188f3f0d256c206da7f6bd40e26984757c881b48fea59902d837924ae679bba741823fd747f8fc46e8fc994761c3c87ef49f50984e742efe44bd43dac79e549d3604d60710c269a13d9d8d98f9b76736f48080817e9f59ab0c38ce6d862d3d46cc68f34610522fea83db15bbd80756dd377c10a084c49d37a5bac73adb299e98b9e6d36d3db968de3af3f933c378e2943bda017b74e92dd3f1a0f02c233fae1430e1871a46323271e5483510dfab645effbb08562b1594a32c5108dc49e4c726afad61c259245d675a0724bc0e2e0850e8a8ace20b395e125966a01f70ece15c3ee6a2b9687b6eceba45467c08e9f240e8c23f80917493798bd7ad57bc70e0bbe7da96d65d64def2bd160a672b36734e2e238c675203f8d9978a98a232c2d7985f76fd8338b2b4bf85ec9c385727dde63280c5c6d2f390533621d507f91e4ab98e8a1bb943a37814e6dae1bc7e74b1d249206ceab9c8d2bc0f075e1887684f74072f01393cc7ae01ec242c07fdbd901d4aca8f1a21595f5a6c1ba7bfcbea346d9c7ebefc1948da15930429c9131bfe226cc7f5c05f2713cc17036d9b7f6bf39f0633ca7d63812a6fc8ed689785b90631a293754f43d32e5a22bf4cd1aa4721a6fcf68b63a797ba00be2c3613590247749359428a1a8b9d65dcc1950cb0cb00d6a1c0441ee749ef8f4fc422c7f893e42a87db1cbb8036ea196ef0a2dc12b60a8296da49bfa23ca777b85a2b206b4c2d7cfc7e81fdc0bdeaff56e53f43cd49bfbc4c295f0782a9041d67dcee987910548cc07ac452b9ee41bb5b1d15fee61ac3fb24b2259c57fdf786e3ee2a4e6d34c7ae1e9ba9585a2a049a33ab4295aade6f7b5ebe05ca3a759eb41c663416c099e1f60d3e529cce896c751ed825abdc1ebd16d4cd675908d41b6f5b627e43a70c153859c99ddfa3d6d86d8076babfa8b8de925fc9b4783a108c160d61fb13342b79084ef0335e375e8e62deea0a4663a026a9f9d2ccabb4280bab1f843a1ad0b22f49503bbba61952ea137e72d5efdd8d55f035b2a975d3bfc25d39ca4443fce48bc427680c8bf4ecb0cd811c1cf020b7ca2307567b65481158e1ed60fa28b64ad20e4e3778f109e1cf42e3a98c8aa1999a4e78501b350cc73c3a8a8835522608948657f0ca569f13e08f0c1f1d3d48c3f8e0418ae97f19ef2b0559d9410caea047e10c9cb";

/// Bootstrap node configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapNode {
    /// Network address (IP:port or domain:port)
    pub address: String,
    /// Dilithium public key (hex encoded)
    pub pubkey: String,
}

/// Default bootstrap nodes for mainnet
pub fn mainnet_bootstrap_nodes() -> Vec<BootstrapNode> {
    vec![
        BootstrapNode {
            address: "bootstrap1.truthlinked.io:19080".to_string(),
            pubkey: VALIDATOR1_DILITHIUM_PUBKEY.to_string(),
        },
        BootstrapNode {
            address: "bootstrap2.truthlinked.io:19080".to_string(),
            pubkey: VALIDATOR2_DILITHIUM_PUBKEY.to_string(),
        },
        BootstrapNode {
            address: "bootstrap3.truthlinked.io:19080".to_string(),
            pubkey: VALIDATOR3_DILITHIUM_PUBKEY.to_string(),
        },
    ]
}

/// Default bootstrap nodes for testnet
pub fn testnet_bootstrap_nodes() -> Vec<BootstrapNode> {
    vec![
        BootstrapNode {
            address: "127.0.0.1:19080".to_string(),
            pubkey: VALIDATOR1_DILITHIUM_PUBKEY.to_string(),
        },
        BootstrapNode {
            address: "127.0.0.1:19082".to_string(),
            pubkey: VALIDATOR2_DILITHIUM_PUBKEY.to_string(),
        },
        BootstrapNode {
            address: "127.0.0.1:19084".to_string(),
            pubkey: VALIDATOR3_DILITHIUM_PUBKEY.to_string(),
        },
    ]
}

/// Peer information exchanged during discovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Dilithium public key
    pub pubkey: Vec<u8>,
    /// Network addresses this peer is reachable at
    pub addresses: Vec<String>,
    /// Current block height
    pub height: u64,
    /// Timestamp of last update
    pub timestamp: u64,
}

/// Peer discovery manager
pub struct PeerDiscovery {
    /// Known peers with metadata
    known_peers: std::sync::Arc<tokio::sync::RwLock<std::collections::HashMap<String, PeerInfo>>>,
}

impl PeerDiscovery {
    pub fn new() -> Self {
        Self {
            known_peers: std::sync::Arc::new(tokio::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
        }
    }

    /// Add a peer with metadata
    pub async fn add_peer(&self, address: String, peer_info: PeerInfo) {
        let mut peers = self.known_peers.write().await;
        if peers.len() >= gp::get_usize(gp::PARAM_DISCOVERY_MAX_PEERS) {
            // Evict oldest peer to make room.
            if let Some((oldest_key, _)) = peers
                .iter()
                .min_by_key(|(_, info)| info.timestamp)
                .map(|(k, v)| (k.clone(), v.clone()))
            {
                peers.remove(&oldest_key);
            }
        }
        peers.insert(address, peer_info);
    }

    /// Update peer height
    pub async fn update_peer_height(&self, address: &str, height: u64) {
        if let Some(peer) = self.known_peers.write().await.get_mut(address) {
            peer.height = height;
            peer.timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
        }
    }

    /// Get all known peers (addresses)
    pub async fn get_peers(&self) -> Vec<String> {
        self.known_peers.read().await.keys().cloned().collect()
    }

    /// Get all known peers with full metadata
    pub async fn get_peer_infos(&self) -> Vec<PeerInfo> {
        self.known_peers.read().await.values().cloned().collect()
    }

    /// Get peer info
    pub async fn get_peer_info(&self, address: &str) -> Option<PeerInfo> {
        self.known_peers.read().await.get(address).cloned()
    }

    /// Remove stale peers based on TTL.
    pub async fn prune_stale(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let ttl = gp::get_u64(gp::PARAM_DISCOVERY_PEER_TTL_SECS);
        let mut peers = self.known_peers.write().await;
        peers.retain(|_, info| {
            if now == 0 {
                true
            } else {
                now.saturating_sub(info.timestamp) <= ttl
            }
        });
    }

    /// Load bootstrap nodes based on network
    pub fn load_bootstrap_nodes(is_testnet: bool) -> Vec<BootstrapNode> {
        if is_testnet {
            testnet_bootstrap_nodes()
        } else {
            mainnet_bootstrap_nodes()
        }
    }
}
