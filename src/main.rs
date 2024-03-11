use std::{time::Instant, collections::HashMap, error::Error};
use semaphore_depth_config::{get_depth_index, get_supported_depth_count};
use semaphore_depth_macros::array_for_depths;
use witness::{Graph, init_graph};
use ark_ff::Field;
use num_bigint::{BigInt, Sign, ToBigInt};

use std::{
    convert::TryInto,
    sync::Mutex,
    {os::raw::c_int, io::BufReader},
    fs::File,
    path::Path
};

use wasmer::{Module, Store};
use once_cell::sync::{Lazy, OnceCell};

use ark_bn254::Bn254;
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::{prepare_verifying_key, Groth16, Proof};
use ark_ec::AffineRepr;
use ark_ff::UniformRand;
use ark_groth16::{ProvingKey};
use ark_relations::r1cs::ConstraintMatrices;
use ark_bn254::{Fr};
use ark_std::str::FromStr;
extern crate hex;
use hex::decode;

use ark_circom::{ethereum, CircomBuilder, CircomConfig, circom::CircomReduction, WitnessCalculator};
use ark_std::rand::thread_rng;

use ruint::aliases::U256;

type GrothBn = Groth16<Bn254>;

mod zkey;
pub use zkey::{read_zkey, read_zkey_from_include_bytes};

mod serialization;
pub use serialization::{SerializableInputs, SerializableProof};

const GRAPH_BYTES: &[u8] = include_bytes!("../graph.bin");

static WITHESS_GRAPH: Lazy<Graph> = Lazy::new(|| init_graph(&GRAPH_BYTES).expect("Failed to initialize Graph"));

const ZKEY_BYTES: &[u8] = include_bytes!("../build/proof_of_passport_final.zkey");

static ZKEY: Lazy<(ProvingKey<Bn254>, ConstraintMatrices<Fr>)> = Lazy::new(|| {
    read_zkey_from_include_bytes(ZKEY_BYTES).expect("Failed to read arkzkey")
});

pub fn zkey() -> &'static (ProvingKey<Bn254>, ConstraintMatrices<Fr>) {
    &ZKEY
}

const WASM: &[u8] = include_bytes!("../build/proof_of_passport_js/proof_of_passport.wasm");

static WITNESS_CALCULATOR: OnceCell<Mutex<WitnessCalculator>> = OnceCell::new();

fn fnv1a(s: &str) -> u64 {
    let mut hash: u64 = 0xCBF29CE484222325;
    for c in s.bytes() {
        hash ^= c as u64;
        hash = hash.wrapping_mul(0x100000001B3);
    }
    hash
}


pub fn witness_calculator() -> &'static Mutex<WitnessCalculator> {
    WITNESS_CALCULATOR.get_or_init(|| {
        let store = Store::default();
        let module = Module::from_binary(&store, WASM).expect("WASM should be valid");
        let result =
            WitnessCalculator::from_module(module).expect("Failed to create WitnessCalculator");
        Mutex::new(result)
    })
}

fn main() -> Result<(), Box<dyn Error>> {

    // let data = r#"
    // {
    //     "a": ["3"],
    //     "b": ["3"]
    // }"#;

    // let data = r#"
    // {
    //     "identityNullifier": ["0x099ab25e555083e656e9ec66a5368d1edd3314bd2dc77553813c5145d37326a3"],
    //     "identityTrapdoor": ["0x1db60e4cd8008edd85c68d461bf00d04f1620372f45c6ffacdb1a318791c2dd3"],
    //     "treePathIndices": [
    //         "0x0",
    //         "0x0",
    //         "0x0",
    //         "0x0",
    //         "0x0",
    //         "0x0",
    //         "0x0",
    //         "0x0",
    //         "0x0",
    //         "0x0",
    //         "0x0",
    //         "0x0",
    //         "0x0",
    //         "0x0",
    //         "0x0",
    //         "0x0"
    //     ],
    //     "treeSiblings": [
    //         "0x0",
    //         "0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864",
    //         "0x1069673dcdb12263df301a6ff584a7ec261a44cb9dc68df067a4774460b1f1e1",
    //         "0x18f43331537ee2af2e3d758d50f72106467c6eea50371dd528d57eb2b856d238",
    //         "0x07f9d837cb17b0d36320ffe93ba52345f1b728571a568265caac97559dbc952a",
    //         "0x2b94cf5e8746b3f5c9631f4c5df32907a699c58c94b2ad4d7b5cec1639183f55",
    //         "0x2dee93c5a666459646ea7d22cca9e1bcfed71e6951b953611d11dda32ea09d78",
    //         "0x078295e5a22b84e982cf601eb639597b8b0515a88cb5ac7fa8a4aabe3c87349d",
    //         "0x2fa5e5f18f6027a6501bec864564472a616b2e274a41211a444cbe3a99f3cc61",
    //         "0x0e884376d0d8fd21ecb780389e941f66e45e7acce3e228ab3e2156a614fcd747",
    //         "0x1b7201da72494f1e28717ad1a52eb469f95892f957713533de6175e5da190af2",
    //         "0x1f8d8822725e36385200c0b201249819a6e6e1e4650808b5bebc6bface7d7636",
    //         "0x2c5d82f66c914bafb9701589ba8cfcfb6162b0a12acf88a8d0879a0471b5f85a",
    //         "0x14c54148a0940bb820957f5adf3fa1134ef5c4aaa113f4646458f270e0bfbfd0",
    //         "0x190d33b12f986f961e10c0ee44d8b9af11be25588cad89d416118e4bf4ebe80c",
    //         "0x22f98aa9ce704152ac17354914ad73ed1167ae6596af510aa5b3649325e06c92"
    //     ],
    //     "externalNullifier": ["0x00fd3a1e9736c12a5d4a31f26362b577ccafbd523d358daf40cdc04d90e17f77"],
    //     "signalHash": ["0x00bc6bb462e38af7da48e0ae7b5cbae860141c04e5af2cf92328cd6548df111f"]
    // }"#;

    // CLASSIC WITNESS GEN
    // let mut inputs: HashMap<String, Vec<num_bigint::BigInt>> = HashMap::new();
    // let values = inputs.entry("a".to_string()).or_insert_with(Vec::new);
    // values.push(3.into());

    // let mrz_vec: Vec<String> = vec![ "97", "91", "95", "31", "88", "80", "60", "70", "82", "65", "68", "85", "80", "79", "78", "84", "60", "60", "65", "76", "80", "72", "79", "78", "83", "69", "60", "72", "85", "71", "85", "69", "83", "60", "65", "76", "66", "69", "82", "84", "60", "60", "60", "60", "60", "60", "60", "60", "60", "50", "52", "72", "66", "56", "49", "56", "51", "50", "52", "70", "82", "65", "48", "52", "48", "50", "49", "49", "49", "77", "51", "49", "49", "49", "49", "49", "53", "60", "60", "60", "60", "60", "60", "60", "60", "60", "60", "60", "60", "60", "60", "48", "50"].iter().map(|&s| s.to_string()).collect();
    // let reveal_bitmap_vec: Vec<String> = vec![ "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1"].iter().map(|&s| s.to_string()).collect();
    // let data_hashes_vec: Vec<String> = vec![ "48", "130", "1", "37", "2", "1", "0", "48", "11", "6", "9", "96", "134", "72", "1", "101", "3", "4", "2", "1", "48", "130", "1", "17", "48", "37", "2", "1", "1", "4", "32", "176", "223", "31", "133", "108", "84", "158", "102", "70", "11", "165", "175", "196", "12", "201", "130", "25", "131", "46", "125", "156", "194", "28", "23", "55", "133", "157", "164", "135", "136", "220", "78", "48", "37", "2", "1", "2", "4", "32", "190", "82", "180", "235", "222", "33", "79", "50", "152", "136", "142", "35", "116", "224", "6", "242", "156", "141", "128", "248", "10", "61", "98", "86", "248", "45", "207", "210", "90", "232", "175", "38", "48", "37", "2", "1", "3", "4", "32", "0", "194", "104", "108", "237", "246", "97", "230", "116", "198", "69", "110", "26", "87", "17", "89", "110", "199", "108", "250", "36", "21", "39", "87", "110", "102", "250", "213", "174", "131", "171", "174", "48", "37", "2", "1", "11", "4", "32", "136", "155", "87", "144", "111", "15", "152", "127", "85", "25", "154", "81", "20", "58", "51", "75", "193", "116", "234", "0", "60", "30", "29", "30", "183", "141", "72", "247", "255", "203", "100", "124", "48", "37", "2", "1", "12", "4", "32", "41", "234", "106", "78", "31", "11", "114", "137", "237", "17", "92", "71", "134", "47", "62", "78", "189", "233", "201", "214", "53", "4", "47", "189", "201", "133", "6", "121", "34", "131", "64", "142", "48", "37", "2", "1", "13", "4", "32", "91", "222", "210", "193", "62", "222", "104", "82", "36", "41", "138", "253", "70", "15", "148", "208", "156", "45", "105", "171", "241", "195", "185", "43", "217", "162", "146", "201", "222", "89", "238", "38", "48", "37", "2", "1", "14", "4", "32", "76", "123", "216", "13", "51", "227", "72", "245", "59", "193", "238", "166", "103", "49", "23", "164", "171", "188", "194", "197", "156", "187", "249", "28", "198", "95", "69", "15", "182", "56", "54", "38", "128", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "9", "72"].iter().map(|&s| s.to_string()).collect();
    // let datahashes_padded_length_str: String = "320".to_string();
    // let e_content_bytes_vec: Vec<String> = vec![ "49", "102", "48", "21", "6", "9", "42", "134", "72", "134", "247", "13", "1", "9", "3", "49", "8", "6", "6", "103", "129", "8", "1", "1", "1", "48", "28", "6", "9", "42", "134", "72", "134", "247", "13", "1", "9", "5", "49", "15", "23", "13", "49", "57", "49", "50", "49", "54", "49", "55", "50", "50", "51", "56", "90", "48", "47", "6", "9", "42", "134", "72", "134", "247", "13", "1", "9", "4", "49", "34", "4", "32", "32", "85", "108", "174", "127", "112", "178", "182", "8", "43", "134", "123", "192", "211", "131", "66", "184", "240", "212", "181", "240", "180", "106", "195", "24", "117", "54", "129", "19", "10", "250", "53"].iter().map(|&s| s.to_string()).collect();
    // let pubkey_vec: Vec<String> = vec![ "14877258137020857405", "14318023465818440622", "669762396243626034", "2098174905787760109", "13512184631463232752", "1151033230807403051", "1750794423069476136", "5398558687849555435", "7358703642447293896", "14972964178681968444", "17927376393065624666", "12136698642738483635", "13028589389954236416", "11728294669438967583", "11944475542136244450", "12725379692537957031", "16433947280623454013", "13881303350788339044", "8072426876492282526", "6117387215636660433", "4538720981552095319", "1804042726655603403", "5977651198873791747", "372166053406449710", "14344596050894147197", "10779070237704917237", "16780599956687811964", "17935955203645787728", "16348714160740996118", "15226818430852970175", "10311930392912784455", "16078982568357050303"].iter().map(|&s| s.to_string()).collect();
    // let signature_vec: Vec<String> = vec![ "5246435566823387901", "994140068779018945", "15914471451186462512", "7880571667552251248", "6469307986104572621", "12461949630634658221", "12450885696843643385", "13947454655189776216", "15974551328200116785", "931381626091656069", "1385903161379602775", "12855786061091617297", "15094260651801937779", "13471621228825251570", "17294887199620944108", "14311703967543697647", "12973402331891058776", "4499641933342092059", "10578231994395748441", "10761169031539003508", "9946908810756942959", "4164708910663312563", "1838078345835967157", "3031966336456751199", "12952597393846567366", "7709884308070068222", "2297541532764959033", "6155424118644397184", "10223511940510133693", "2888993604729528860", "2817846539210919674", "9919760476291903645"].iter().map(|&s| s.to_string()).collect();
    // let address_str: String = "0xEde0fA5A7b196F512204f286666E5eC03E1005D2".to_string();

    // parse_and_insert(&mut inputs, "mrz", mrz_vec.iter().map(AsRef::as_ref).collect());
    // parse_and_insert(&mut inputs, "reveal_bitmap", reveal_bitmap_vec.iter().map(AsRef::as_ref).collect());
    // parse_and_insert(&mut inputs, "dataHashes", data_hashes_vec.iter().map(AsRef::as_ref).collect());
    // parse_and_insert(&mut inputs, "eContentBytes", e_content_bytes_vec.iter().map(AsRef::as_ref).collect());
    // parse_and_insert(&mut inputs, "signature", signature_vec.iter().map(AsRef::as_ref).collect());
    // parse_and_insert(&mut inputs, "pubkey", pubkey_vec.iter().map(AsRef::as_ref).collect());

    // let address_bigint = BigInt::from_bytes_be(Sign::Plus, &decode(&address_str[2..])?);
    // inputs.insert("address".to_string(), vec![address_bigint]);

    // let datahashes_padded_length_i32 = datahashes_padded_length_str.parse::<i32>().expect("Failed to parse datahashes_padded_length to i32");
    // let datahashes_padded_length_bigint = BigInt::from(datahashes_padded_length_i32);
    // inputs.insert("datahashes_padded_length".to_string(), vec![datahashes_padded_length_bigint]);

    // let full_assignment = witness_calculator()
    //     .lock()
    //     .expect("Failed to lock witness calculator")
    //     .calculate_witness_element::<Bn254, _>(inputs, false)
    //     .map_err(|e| e.to_string())?;

    // RUST WITNESS GEN    
    let passport_data = r#"
    {
        "mrz":["97","91","95","31","88","80","60","70","82","65","68","85","80","79","78","84","60","60","65","76","80","72","79","78","83","69","60","72","85","71","85","69","83","60","65","76","66","69","82","84","60","60","60","60","60","60","60","60","60","50","52","72","66","56","49","56","51","50","52","70","82","65","48","52","48","50","49","49","49","77","51","49","49","49","49","49","53","60","60","60","60","60","60","60","60","60","60","60","60","60","60","48","50"],
        "dataHashes":["48","130","1","37","2","1","0","48","11","6","9","96","134","72","1","101","3","4","2","1","48","130","1","17","48","37","2","1","1","4","32","176","223","31","133","108","84","158","102","70","11","165","175","196","12","201","130","25","131","46","125","156","194","28","23","55","133","157","164","135","136","220","78","48","37","2","1","2","4","32","190","82","180","235","222","33","79","50","152","136","142","35","116","224","6","242","156","141","128","248","10","61","98","86","248","45","207","210","90","232","175","38","48","37","2","1","3","4","32","0","194","104","108","237","246","97","230","116","198","69","110","26","87","17","89","110","199","108","250","36","21","39","87","110","102","250","213","174","131","171","174","48","37","2","1","11","4","32","136","155","87","144","111","15","152","127","85","25","154","81","20","58","51","75","193","116","234","0","60","30","29","30","183","141","72","247","255","203","100","124","48","37","2","1","12","4","32","41","234","106","78","31","11","114","137","237","17","92","71","134","47","62","78","189","233","201","214","53","4","47","189","201","133","6","121","34","131","64","142","48","37","2","1","13","4","32","91","222","210","193","62","222","104","82","36","41","138","253","70","15","148","208","156","45","105","171","241","195","185","43","217","162","146","201","222","89","238","38","48","37","2","1","14","4","32","76","123","216","13","51","227","72","245","59","193","238","166","103","49","23","164","171","188","194","197","156","187","249","28","198","95","69","15","182","56","54","38","128","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","9","72"],
        "datahashes_padded_length":["320"],
        "eContentBytes":["49","102","48","21","6","9","42","134","72","134","247","13","1","9","3","49","8","6","6","103","129","8","1","1","1","48","28","6","9","42","134","72","134","247","13","1","9","5","49","15","23","13","49","57","49","50","49","54","49","55","50","50","51","56","90","48","47","6","9","42","134","72","134","247","13","1","9","4","49","34","4","32","32","85","108","174","127","112","178","182","8","43","134","123","192","211","131","66","184","240","212","181","240","180","106","195","24","117","54","129","19","10","250","53"],
        "pubkey":["14877258137020857405","14318023465818440622","669762396243626034","2098174905787760109","13512184631463232752","1151033230807403051","1750794423069476136","5398558687849555435","7358703642447293896","14972964178681968444","17927376393065624666","12136698642738483635","13028589389954236416","11728294669438967583","11944475542136244450","12725379692537957031","16433947280623454013","13881303350788339044","8072426876492282526","6117387215636660433","4538720981552095319","1804042726655603403","5977651198873791747","372166053406449710","14344596050894147197","10779070237704917237","16780599956687811964","17935955203645787728","16348714160740996118","15226818430852970175","10311930392912784455","16078982568357050303"],
        "signature":["5246435566823387901","994140068779018945","15914471451186462512","7880571667552251248","6469307986104572621","12461949630634658221","12450885696843643385","13947454655189776216","15974551328200116785","931381626091656069","1385903161379602775","12855786061091617297","15094260651801937779","13471621228825251570","17294887199620944108","14311703967543697647","12973402331891058776","4499641933342092059","10578231994395748441","10761169031539003508","9946908810756942959","4164708910663312563","1838078345835967157","3031966336456751199","12952597393846567366","7709884308070068222","2297541532764959033","6155424118644397184","10223511940510133693","2888993604729528860","2817846539210919674","9919760476291903645"],
        "reveal_bitmap":["1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1","1"],
        "address":["0x70997970c51812dc3a010c7d01b50e0d17dc79c8"]
    }"#;


    fn decimal_to_hex(decimal_string: &str) -> String {
        format!("{:02x}", decimal_string.parse::<u8>().unwrap())
    }
    
    let passport_data: serde_json::Value = serde_json::from_str(passport_data).unwrap();
    let mut passport_data_hex = passport_data.clone();
    
    for key in passport_data.as_object().unwrap().keys() {
        if key != "address" {
            let values = passport_data[key].as_array().unwrap();
            let hex_values: Vec<String> = values.iter().map(|v| decimal_to_hex(v.as_str().unwrap())).collect();
            passport_data_hex[key] = serde_json::Value::Array(hex_values.iter().map(|s| serde_json::Value::String(s.clone())).collect());
        }
    }
    
    let passport_data_hex_str = serde_json::to_string(&passport_data_hex).unwrap();
    println!("passport_data: {:?}", passport_data.clone());
    println!("passport_data_hex_str: {:?}", passport_data_hex_str.clone());
    let inputs: HashMap<String, Vec<U256>> = serde_json::from_str(passport_data).unwrap();
    println!("inputs: {:?}", inputs.clone());

    // JUST SOME LOGS
    // let graph_list: Vec<_> = WITHESS_GRAPH.input_mapping.iter().filter(|x| x.hash != 0).collect();
    // eprintln!("graph_list: {:?}", graph_list);

    // let inputs_string: HashMap<String, Vec<String>> = inputs
    //     .clone()
    //     .into_iter()
    //     .map(|(k, v)| (k, v.into_iter().map(|x| format!("{:x}", x)).collect()))
    //     .collect();

    // eprintln!("inputs_string: {:?}", inputs_string.clone());

    // let input_bigint: HashMap<String, Vec<BigInt>> = inputs_string
    //     .into_iter()
    //     .map(|(k, v)| {
    //         let parsed_data: Vec<BigInt> = v.into_iter()
    //             .filter_map(|s| s.parse::<u128>().ok().and_then(|num| num.to_bigint()))
    //             .collect();
    //         (k, parsed_data)
    //     })
    //     .collect();

    // let input_list: Vec<String> = inputs.keys().cloned().collect();
    // eprintln!("input_list: {:?}", input_list);

    // let input_hash_list: Vec<_> = input_list.iter().map(|x| fnv1a(x)).collect();
    // eprintln!("input_hash_list: {:?}", input_hash_list);

    // eprintln!("input_bigint: {:?}", input_bigint.clone());

    let now = Instant::now();
    for _ in 0..10 {
        let w = witness::calculate_witness(inputs.clone(), &WITHESS_GRAPH).unwrap();
    }
    eprintln!("Calculation took: {:?}", now.elapsed() / 10);

    let witness = witness::calculate_witness(inputs.clone(), &WITHESS_GRAPH).unwrap();

    let full_assignment = witness
        .into_iter()
        .map(|x| Fr::from_str(&x.to_string()).unwrap())
        .collect::<Vec<_>>();

    println!("full_assignment {:?}", full_assignment);




    // GEN AND VERIF PROOF (METHOD 1)
    // let (params, matrices) = zkey();

    // let mut rng = thread_rng();
    // use ark_std::UniformRand;
    // let num_inputs = matrices.num_instance_variables;
    // let num_constraints = matrices.num_constraints;
    // let rng = &mut rng;

    // let r = ark_bn254::Fr::rand(rng);
    // let s = ark_bn254::Fr::rand(rng);

    // let proof = Groth16::<Bn254, CircomReduction>::create_proof_with_reduction_and_matrices(
    //     &params,
    //     r,
    //     s,
    //     &matrices,
    //     num_inputs,
    //     num_constraints,
    //     full_assignment.as_slice(),
    // )
    // .unwrap();
    // println!("proof: {:?}", proof.clone());

    // let pvk = Groth16::<Bn254>::process_vk(&params.vk).unwrap();
    // let inputs = &full_assignment[1..num_inputs];
    // let verified = Groth16::<Bn254>::verify_with_processed_vk(&pvk, inputs, &proof).unwrap();
    // println!("verified: {:?}", verified);

    // assert!(verified);



    
    // GEN AND VERIF PROOF (METHOD 2)
    let mut rng = thread_rng();
    let rng = &mut rng;
    let r = ark_bn254::Fr::rand(rng);
    let s = ark_bn254::Fr::rand(rng);
    
    let zkey = zkey();
    let public_inputs = full_assignment.as_slice()[1..zkey.1.num_instance_variables].to_vec();
    // Extract the public inputs from the full assignment
    print!("full_assignment: {:?}", full_assignment.clone());
    print!("zkey.1.num_instance_variables: {:?}", zkey.1.num_instance_variables);
    let serialized_inputs = SerializableInputs(public_inputs);
    print!("serialized_inputs: {:?}", serialized_inputs.clone());

    let ark_proof = Groth16::<_, CircomReduction>::create_proof_with_reduction_and_matrices(
        &zkey.0,
        r,
        s,
        &zkey.1,
        zkey.1.num_instance_variables,
        zkey.1.num_constraints,
        full_assignment.as_slice(),
    );
    let proof = ark_proof.map_err(|e| e.to_string())?;
    print!("proof: {:?}", proof.clone());
    let serialized_proof = SerializableProof(proof);
        
    // Proof verification
    let verify_res: Result<bool, String> = verify_proof2(serialized_proof, serialized_inputs);
    print!("Verification result: {:?}", verify_res.clone().unwrap());
    assert!(verify_res.is_ok());

    Ok(())
}

fn parse_and_insert(hash_map: &mut HashMap<String, Vec<BigInt>>, key: &str, data: Vec<&str>) {
    let parsed_data: Vec<BigInt> = data.into_iter()
        .filter_map(|s| s.parse::<u128>().ok().and_then(|num| num.to_bigint()))
        .collect();
    hash_map.insert(key.to_string(), parsed_data);
}


pub fn verify_proof2(
    serialized_proof: SerializableProof,
    serialized_inputs: SerializableInputs,
) -> Result<bool, String> {
    let start = Instant::now();
    let zkey = zkey();
    let pvk = prepare_verifying_key(&zkey.0.vk);

    let proof_verified_result =
        GrothBn::verify_with_processed_vk(&pvk, &serialized_inputs.0, &serialized_proof.0);

    let verification_duration = start.elapsed();
    println!("Verification time 2: {:?}", verification_duration);
    println!("proof_verified_result: {:?}", proof_verified_result);

    match proof_verified_result {
        Ok(proof_verified) => Ok(proof_verified),
        Err(e) => Err(e.to_string()),
    }
}
// still takes the default circuit, would have to fork the lib to solve this.
// input_hash_list: [
//     855802234983132701,
//     4224415288178834212,
//     1673076945917317811,
//     3619300247054241923,
//     5209776106289718733,
//     3518692415938519709,
//     11350379717400383902,
//     566421219394571564
// ]

// hash: 12010952635498483723,
// hash: 11178839370693850190,
// hash: 5216176190592276341,
// hash: 11961648619945407412,
// hash: 17193227233913701591,
// hash: 13333294437656739064,

