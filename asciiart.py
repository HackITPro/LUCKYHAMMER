from pyfiglet import figlet_format
import random

fonts = ['1943____', '3-d', '3x5', '4x4_offr', '5lineoblique', '5x7', '5x8', '64f1____', '6x10', '6x9', 'acrobatic',
         'advenger', 'alligator2', 'alligator', 'alphabet', 'aquaplan', 'arrows', 'asc_____', 'ascii___', 'assalt_m',
         'asslt__m', 'atc_____', 'atc_gran', 'avatar', 'a_zooloo', 'banner3-D', 'banner3', 'banner4', 'banner',
         'barbwire', 'basic', 'battle_s', 'battlesh', 'baz__bil', 'beer_pub', 'bell', 'bigchief', 'big', 'binary',
         'block', 'b_m__200', 'briteb', 'britebi', 'brite', 'britei', 'broadway', 'bubble_b', 'bubble', 'bubble__',
         'bulbhead', 'c1______', 'c2______', 'calgphy2', 'caligraphy', 'c_ascii_', 'catwalk', 'caus_in_', 'c_consen',
         'char1___', 'char2___', 'char3___', 'char4___', 'charact1', 'charact2', 'charact3', 'charact4', 'charact5',
         'charact6', 'characte', 'charset_', 'chartr', 'chartri', 'chunky', 'clb6x10', 'clb8x10', 'clb8x8', 'cli8x8',
         'clr4x6', 'clr5x10', 'clr5x6', 'clr5x8', 'clr6x10', 'clr6x6', 'clr6x8', 'clr7x10', 'clr7x8', 'clr8x10',
         'clr8x8', 'coil_cop', 'coinstak', 'colossal', 'computer', 'com_sen_', 'contessa', 'contrast', 'convoy__',
         'cosmic', 'cosmike', 'courb', 'courbi', 'cour', 'couri', 'crawford', 'cricket', 'cursive', 'cyberlarge',
         'cybermedium', 'cybersmall', 'dcs_bfmo', 'd_dragon', 'decimal', 'deep_str', 'defleppard', 'demo_1__',
         'demo_2__', 'demo_m__', 'devilish', 'diamond', 'digital', 'doh', 'doom', 'dotmatrix', 'double', 'drpepper',
         'druid___', 'dwhistled', 'ebbs_1__', 'ebbs_2__', 'eca_____', 'e__fist_', 'eftichess', 'eftifont', 'eftipiti',
         'eftirobot', 'eftitalic', 'eftiwall', 'eftiwater', 'epic', 'etcrvs__', 'f15_____', 'faces_of', 'fairligh',
         'fair_mea', 'fantasy_', 'fbr12___', 'fbr1____', 'fbr2____', 'fbr_stri', 'fbr_tilt', 'fender', 'finalass',
         'fireing_', 'flyn_sh', 'fourtops', 'fp1_____', 'fp2_____', 'fraktur', 'funky_dr', 'future_1', 'future_2',
         'future_3', 'future_4', 'future_5', 'future_6', 'future_7', 'future_8', 'fuzzy', 'gauntlet', 'ghost_bo',
         'goofy', 'gothic', 'gothic__', 'graceful', 'gradient', 'graffiti', 'grand_pr', 'greek', 'green_be',
         'hades___', 'heavy_me', 'helvb', 'helvbi', 'helv', 'helvi', 'heroboti', 'hex', 'high_noo', 'hills___',
         'hollywood', 'home_pak', 'house_of', 'hypa_bal', 'hyper___', 'inc_raw_', 'invita', 'isometric1', 'isometric2',
         'isometric3', 'isometric4', 'italic', 'italics_', 'ivrit', 'jazmine', 'jerusalem', 'joust___', 'katakana',
         'kban', 'kgames_i', 'kik_star', 'krak_out', 'larry3d', 'lazy_jon', 'lcd', 'lean', 'letters', 'letterw3',
         'letter_w', 'lexible_', 'linux', 'lockergnome', 'mad_nurs', 'madrid', 'magic_ma', 'marquee', 'master_o',
         'maxfour', 'mayhem_d', 'mcg_____', 'mig_ally', 'mike', 'mini', 'mirror', 'mnemonic', 'modern__', 'morse',
         'moscow', 'mshebrew210', 'nancyj-fancy', 'nancyj', 'nancyj-underlined', 'new_asci', 'nfi1____', 'nipples',
         'notie_ca', 'npn_____', 'ntgreek', 'nvscript', 'o8', 'octal', 'odel_lak', 'ogre', 'ok_beer_', 'os2',
         'outrun__', 'pacos_pe', 'panther_', 'pawn_ins', 'pawp', 'peaks', 'pebbles', 'pepper', 'phonix__', 'platoon2',
         'platoon_', 'pod_____', 'poison', 'p_s_h_m_', 'p_skateb', 'puffy', 'pyramid', 'r2-d2___', 'rad_____',
         'radical_', 'rad_phan', 'rainbow_', 'rally_s2', 'rally_sp', 'rampage_', 'rastan__', 'raw_recu', 'rci_____',
         'rectangles', 'relief2', 'relief', 'rev', 'ripper!_', 'road_rai', 'rockbox_', 'rok_____', 'roman', 'roman___',
         'rot13', 'rounded', 'rowancap', 'rozzo', 'runic', 'runyc', 'sansb', 'sansbi', 'sans', 'sansi', 'sblood',
         'sbookb', 'sbookbi', 'sbook', 'sbooki', 'script', 'script__', 'serifcap', 'shadow', 'shimrod', 'short',
         'skateord', 'skateroc', 'skate_ro', 'sketch_s', 'slant', 'slide', 'slscript', 'small', 'sm______', 'smisome1',
         'smkeyboard', 'smscript', 'smshadow', 'smslant', 'smtengwar', 'space_op', 'spc_demo', 'speed', 'stacey',
         'stampatello', 'standard', 'star_war', 'starwars', 'stealth_', 'stellar', 'stencil1', 'stencil2', 'stop',
         'straight', 'street_s', 'subteran', 'super_te', 'tanja', 'tav1____', 'taxi____', 'tec1____', 'tec_7000',
         'tecrvs__', 'tengwar', 'term', 'thick', 'thin', 'threepoint', 'ticks', 'ticksslant', 'tiles', 'times',
         'timesofl', 'tinker-toy', 'ti_pan__', 't__of_ap', 'tomahawk', 'tombstone', 'top_duck', 'trashman', 'trek',
         'triad_st', 'ts1_____', 'tsalagi', 'tsm_____', 'tsn_base', 'ttyb', 'tty', 'tubular', 'twin_cob', 'twopoint',
         'type_set', 'ucf_fan_', 'ugalympi', 'unarmed_', 'univers', 'usaflag', 'usa_____', 'usa_pq__', 'utopiab',
         'utopiabi', 'utopia', 'utopiai', 'vortron_', 'war_of_w', 'wavy', 'weird', 'whimsy', 'xbriteb', 'xbritebi',
         'xbrite', 'xbritei', 'xchartr', 'xchartri', 'xcourb', 'xcourbi', 'xcour', 'xcouri', 'xhelvb', 'xhelvbi',
         'xhelv', 'xhelvi', 'xsansb', 'xsansbi', 'xsans', 'xsansi', 'xsbookb', 'xsbookbi', 'xsbook', 'xsbooki',
         'xtimes', 'xttyb', 'xtty', 'yie-ar__', 'yie_ar_k', 'zig_zag_', 'zone7___', 'z-pilot_']


def get_art(text, rand=True):
    if rand:
        return figlet_format(text, random.choice(fonts))
    else:
        return figlet_format(text, 'cybermedium')

