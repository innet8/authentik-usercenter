
const themeOverrides = {
    lightThemeOverrides: {
        common: {
            primaryColor: "#0C9189",
            primaryColorHover: "rgba(12, 145, 137, 0.8)",
            borderRadius:'6px',
        },
        Input:{
            heightSmall: "30px",
            heightMedium: "48px",
        },
        Button:{
            heightMedium:'50px',
            fontSizeMedium:'16px',
        },
        Form:{
            labelTextColor:"#84888C",
            asteriskColor:"#DB232C",
            feedbackTextColorError:"#DB232C",
        },
    },
    darkThemeOverrides: {
        common: {
            primaryColor: "#67a050",
            primaryColorHover: "#568342",
            baseColor: "#ffffff",
        },
        Input:{
            heightSmall: "30px",
            heightMedium: "32px",
        }
    },
}
export default themeOverrides
